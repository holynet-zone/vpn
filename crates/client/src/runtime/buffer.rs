use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use crossbeam::queue::SegQueue;

pub struct Buffer {
    data: Vec<u8>
}

impl Buffer {

    pub fn new() -> Self {
        Self {
            data: Vec::new()
        }
    }

    fn reset(&mut self) {
        unsafe { self.data.set_len(0) };
    }
}

impl Read for Buffer {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.data.len() > buf.len() {
            return Ok(0);
        }

        unsafe {
            std::ptr::copy_nonoverlapping(
                self.data.as_ptr(),
                buf.as_mut_ptr(),
                self.data.len()
            );
        }
        Ok(self.data.len())
    }
}

impl Write for Buffer {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.data.capacity() < buf.len() {
            self.data.reserve(buf.len());
        }

        unsafe {
            std::ptr::copy_nonoverlapping(
                buf.as_ptr(),
                self.data.as_mut_ptr(),
                buf.len()
            );
            self.data.set_len(buf.len());
        }
        Ok(buf.len())
    }

     fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

impl Default for Buffer {
    fn default() -> Self {
        Self::new()
    }
}

pub struct BufferPool {
    buffers: SegQueue<Buffer>,
    allocated: AtomicUsize,
    limit: Option<usize>,
}

impl BufferPool {
    pub fn new(limit: Option<usize>) -> Self {
        Self {
            buffers: SegQueue::new(),
            allocated: AtomicUsize::new(0),
            limit,
        }
    }

    pub fn alloc(&self) -> Option<Buffer> {
        if let Some(limit) = self.limit {
            if self.allocated.load(Ordering::Relaxed) >= limit {
                return None;
            }
            self.allocated.fetch_add(1, Ordering::Relaxed);
        }
        Some(self.buffers.pop().unwrap_or_default())
    }

    pub fn release(&self, mut buffer: Buffer) {
        if self.limit.is_some() {
            self.allocated.fetch_sub(1, Ordering::Relaxed);
        }
        buffer.reset();
        self.buffers.push(buffer);
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::new(None)
    }
}

#[cfg(test)]
#[allow(clippy::unused_io_amount)]
mod tests {
    use std::sync::Arc;
    use super::*;
    use std::thread;

    #[test]
    fn basic_read_write() {
        let mut buf = Buffer::new();
        buf.write(&[1, 2, 3]).unwrap();
        let mut output = [0u8; 3];
        assert_eq!(buf.read(&mut output).unwrap(), 3);
        assert_eq!(output, [1, 2, 3]);
    }

    #[test]
    fn buffer_reuse() {
        let pool = BufferPool::new(Some(214748));
        let mut results = vec![(0u128, 0u128); 214748];
        let mut buffers= Vec::new();
        for i in 0..214748 {
            let mut buf = pool.alloc().unwrap();
            buf.write(&[i as u8; 9000]).unwrap();
            buffers.push(buf);
        }
        for i in buffers.into_iter() {
            pool.release(i);
        }
        
        let mut start = std::time::Instant::now();
        for i in 0..214748 {
            start = std::time::Instant::now();
            let mut buf = pool.alloc().unwrap();
            results[i] = (results[i].0, start.elapsed().as_nanos());
            pool.release(buf);
        }

        for i in 0..214748 {
            start = std::time::Instant::now();
            let buf = Vec::<u8>::with_capacity(9000);
            results[i] = (start.elapsed().as_nanos(), results[i].1);
        }
        for (alloc_time, reuse_time) in results {
            if alloc_time > 1000 || reuse_time > 1000 {
                panic!("Allocation or reuse took too long: alloc={}ns, reuse={}ns", alloc_time, reuse_time);
            }
        }
    }

    #[test]
    fn pool_limit() {
        let pool = BufferPool::new(Some(2));

        let b1 = pool.alloc().unwrap();
        let b2 = pool.alloc().unwrap();
        assert!(pool.alloc().is_none());

        pool.release(b1);
        pool.release(b2);

        assert!(pool.alloc().is_some());
        assert!(pool.alloc().is_some());
        assert!(pool.alloc().is_none());
    }

    #[test]
    fn concurrent_access() {
        let pool = BufferPool::new(Some(10));
        let pool = Arc::new(pool);

        let handles: Vec<_> = (0..10).map(|_| {
            let pool = Arc::clone(&pool);
            thread::spawn(move || {
                let mut buf = pool.alloc().unwrap();
                buf.write(&[1; 100]).unwrap();
                pool.release(buf);
            })
        }).collect();

        handles.into_iter().for_each(|h| h.join().unwrap());
    }

    #[test]
    fn zero_alloc_after_warmup() {
        let pool = BufferPool::new(Some(10));
        const REQ_CAP: usize = 1024;

        // warmup
        for _ in 0..10 {
            let mut buf = pool.alloc().unwrap();
            buf.write(&[0; REQ_CAP]).unwrap();
            pool.release(buf);
        }
        
        // check if we can allocate without exceeding the limit
        for _ in 0..10 {
            let buf = pool.alloc().unwrap();
            assert_eq!(buf.data.capacity(), REQ_CAP);
            pool.release(buf);
        }
    }
}