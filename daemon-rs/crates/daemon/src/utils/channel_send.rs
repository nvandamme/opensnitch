use tokio::sync::mpsc;

pub async fn send_with_backpressure<T>(tx: &mpsc::Sender<T>, item: T) -> bool
where
    T: Send,
{
    match tx.try_send(item) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Full(item)) => tx.send(item).await.is_ok(),
        Err(mpsc::error::TrySendError::Closed(_)) => false,
    }
}
