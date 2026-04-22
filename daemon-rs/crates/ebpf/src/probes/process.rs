#![allow(non_snake_case)]

use core::ptr;

use aya_ebpf::{
	helpers::{
		bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
		bpf_probe_read_user, bpf_probe_read_user_str_bytes,
	},
	macros::{map, tracepoint},
	maps::{HashMap, PerCpuArray},
	programs::TracePointContext,
	EbpfContext,
};

use crate::common::process::{
	COMPLETE_ARGS, EV_TYPE_EXEC, EV_TYPE_EXECVEAT, EV_TYPE_SCHED_EXIT, ExecEvent, INCOMPLETE_ARGS,
	MAX_ARGS, TASK_COMM_LEN,
};
use crate::probes::dns::EVENTS;

const EXEC_CACHE_MAX_ENTRIES: u32 = 1024;

const SYSCALL_ARG0_PTR_OFF: usize = 16;
const SYSCALL_ARG1_PTR_OFF: usize = 24;
const EXECVEAT_FILENAME_OFF: usize = 24;
const EXECVEAT_ARGV_OFF: usize = 32;
const SYSCALL_RET_OFF: usize = 16;

#[map]
static EXEC_MAP: HashMap<u64, ExecEvent> = HashMap::with_max_entries(EXEC_CACHE_MAX_ENTRIES, 0);

#[map]
static PROCESS_EVENT_SCRATCH: PerCpuArray<ExecEvent> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
fn event_buf() -> Option<&'static mut ExecEvent> {
	unsafe { PROCESS_EVENT_SCRATCH.get_ptr_mut(0).map(|ptr| &mut *ptr) }
}

#[inline(always)]
fn fill_common_fields(data: &mut ExecEvent) {
	let pid_tgid = bpf_get_current_pid_tgid();
	data.pid = (pid_tgid >> 32) as u32;
	data.uid = (bpf_get_current_uid_gid() & 0xffff_ffff) as u32;
	// Parent PID collection from task_struct requires kernel-layout specific
	// field access; keep unset for now (legacy parser accepts 0).
	data.ppid = 0;
	unsafe {
		let _ = aya_ebpf::helpers::r#gen::bpf_get_current_comm(
			ptr::addr_of_mut!((*data).comm).cast(),
			TASK_COMM_LEN as u32,
		);
	}
}

#[inline(always)]
fn emit_exec_event(data: &ExecEvent) {
	let _ = EVENTS.output(data, 0);
}

#[inline(always)]
fn read_ctx_ptr<T>(ctx: &TracePointContext, offset: usize) -> *const T {
	let mut value: *const T = ptr::null();
	let src = ((ctx.as_ptr() as usize).wrapping_add(offset)) as *const aya_ebpf::cty::c_void;
	let ret = unsafe {
		aya_ebpf::helpers::r#gen::bpf_probe_read(
			(&mut value as *mut *const T).cast(),
			core::mem::size_of::<*const T>() as u32,
			src,
		)
	};
	if ret == 0 {
		value
	} else {
		ptr::null()
	}
}

#[inline(always)]
fn read_ctx_i64(ctx: &TracePointContext, offset: usize) -> i64 {
	let mut value = -1i64;
	let src = ((ctx.as_ptr() as usize).wrapping_add(offset)) as *const aya_ebpf::cty::c_void;
	let ret = unsafe {
		aya_ebpf::helpers::r#gen::bpf_probe_read(
			(&mut value as *mut i64).cast(),
			core::mem::size_of::<i64>() as u32,
			src,
		)
	};
	if ret == 0 {
		value
	} else {
		-1
	}
}

#[inline(always)]
fn fill_filename(dst: &mut [u8], filename_ptr: *const u8) {
	dst[0] = 0;
	if filename_ptr.is_null() {
		return;
	}
	let _ = unsafe { bpf_probe_read_user_str_bytes(filename_ptr, dst) };
}

#[inline(always)]
fn fill_argv(data: &mut ExecEvent, argv: *const *const u8) {
	data.args_count = 0;
	data.args_partial = INCOMPLETE_ARGS;

	if argv.is_null() {
		data.args_partial = COMPLETE_ARGS;
		return;
	}

	let mut i = 0;
	while i < MAX_ARGS {
		let slot = (argv as usize)
			.wrapping_add(i * core::mem::size_of::<*const u8>())
			as *const *const u8;
		let arg_ptr = match unsafe { bpf_probe_read_user(slot) } {
			Ok(ptr) => ptr,
			Err(_) => break,
		};

		if arg_ptr.is_null() {
			data.args_partial = COMPLETE_ARGS;
			break;
		}

		if unsafe { bpf_probe_read_user_str_bytes(arg_ptr, &mut data.args[i]) }.is_err() {
			break;
		}

		data.args_count = data.args_count.saturating_add(1);
		i += 1;
	}
}

#[inline(always)]
fn handle_exec_enter(ev_type: u64, filename_ptr: *const u8, argv_ptr: *const *const u8) -> u32 {
	let Some(data) = event_buf() else {
		return 0;
	};

	fill_common_fields(data);
	data.ev_type = ev_type;

	fill_filename(&mut data.filename, filename_ptr);
	fill_argv(data, argv_ptr);
	emit_exec_event(data);

	let pid_tgid = bpf_get_current_pid_tgid();
	if EXEC_MAP.insert(&pid_tgid, data, 0).is_err() {
		emit_exec_event(data);
	}

	0
}

#[inline(always)]
fn handle_exec_exit(ret_code: i64) -> u32 {
	let pid_tgid = bpf_get_current_pid_tgid();
	if let Some(proc) = EXEC_MAP.get_ptr_mut(&pid_tgid) {
		unsafe {
			(*proc).ret_code = ret_code as u32;
			emit_exec_event(&*proc);
		}
		return 0;
	}

	let Some(data) = event_buf() else {
		return 0;
	};

	fill_common_fields(data);
	data.ev_type = EV_TYPE_EXEC;
	data.ret_code = ret_code as u32;
	data.args_count = 0;
	data.args_partial = COMPLETE_ARGS;
	data.filename[0] = 0;
	data.args[0][0] = 0;
	emit_exec_event(data);

	0
}

#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn tracepoint__syscalls_sys_enter_execve(ctx: TracePointContext) -> u32 {
	handle_exec_enter(
		EV_TYPE_EXEC,
		read_ctx_ptr::<u8>(&ctx, SYSCALL_ARG0_PTR_OFF),
		read_ctx_ptr::<*const u8>(&ctx, SYSCALL_ARG1_PTR_OFF),
	)
}

#[tracepoint(category = "syscalls", name = "sys_enter_execveat")]
pub fn tracepoint__syscalls_sys_enter_execveat(ctx: TracePointContext) -> u32 {
	handle_exec_enter(
		EV_TYPE_EXECVEAT,
		read_ctx_ptr::<u8>(&ctx, EXECVEAT_FILENAME_OFF),
		read_ctx_ptr::<*const u8>(&ctx, EXECVEAT_ARGV_OFF),
	)
}

#[tracepoint(category = "syscalls", name = "sys_exit_execve")]
pub fn tracepoint__syscalls_sys_exit_execve(ctx: TracePointContext) -> u32 {
	handle_exec_exit(read_ctx_i64(&ctx, SYSCALL_RET_OFF))
}

#[tracepoint(category = "syscalls", name = "sys_exit_execveat")]
pub fn tracepoint__syscalls_sys_exit_execveat(ctx: TracePointContext) -> u32 {
	handle_exec_exit(read_ctx_i64(&ctx, SYSCALL_RET_OFF))
}

#[tracepoint(category = "sched", name = "sched_process_exit")]
pub fn tracepoint__sched_sched_process_exit(_ctx: TracePointContext) -> u32 {
	let pid_tgid = bpf_get_current_pid_tgid();
	let Some(data) = event_buf() else {
		return 0;
	};

	fill_common_fields(data);
	data.ev_type = EV_TYPE_SCHED_EXIT;
	emit_exec_event(data);

	if unsafe { EXEC_MAP.get(&pid_tgid) }.is_some() {
		let _ = EXEC_MAP.remove(&pid_tgid);
	}
	0
}