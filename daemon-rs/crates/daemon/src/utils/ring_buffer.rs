use std::collections::VecDeque;

#[derive(Debug, Clone)]
pub(crate) struct RingBuffer<T> {
    buf: VecDeque<T>,
    capacity: usize,
}

impl<T> RingBuffer<T> {
    pub(crate) fn new(capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            buf: VecDeque::with_capacity(cap),
            capacity: cap,
        }
    }

    pub(crate) fn push_overwrite(&mut self, value: T) {
        if self.buf.len() >= self.capacity {
            let _ = self.buf.pop_front();
        }
        self.buf.push_back(value);
    }

    pub(crate) fn set_capacity(&mut self, capacity: usize) {
        self.capacity = capacity.max(1);
        self.trim_to_capacity();
    }

    pub(crate) fn trim_to_capacity(&mut self) {
        while self.buf.len() > self.capacity {
            let _ = self.buf.pop_front();
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.buf.len()
    }

    pub(crate) fn drain_all(&mut self) -> Vec<T> {
        self.buf.drain(..).collect()
    }
}
