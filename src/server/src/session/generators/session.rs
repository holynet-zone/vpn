use std::collections::HashSet;
use crate::session::SessionId;

pub struct SessionIdGenerator {
    current: SessionId,
    start_with: SessionId,
    borrowed: HashSet<SessionId>,
}

impl SessionIdGenerator {
    pub fn new(start_with: SessionId) -> Self {
        SessionIdGenerator {
            current: start_with,
            start_with,
            borrowed: HashSet::new(),
        }
    }

    pub fn next(&mut self) -> Option<SessionId> {
        if self.borrowed.len() == (SessionId::MAX as usize + 1) || self.borrowed.len() == ((SessionId::MAX as usize + 1) - self.start_with as usize){
            return None;
        }

        let initial = self.current;
        loop {
            if !self.borrowed.contains(&self.current) {
                self.borrowed.insert(self.current);
                return Some(self.current);
            }

            self.current = self.current.wrapping_add(1);
            if self.current < self.start_with {
                self.current = self.start_with;
            }

            if self.current == initial {
                return None;
            }
        }
    }

    pub fn release(&mut self, number: SessionId) {
        self.borrowed.remove(&number);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id_generator() {
        let mut generator = SessionIdGenerator::new(0);
        for i in 0..1024 {
            assert_eq!(generator.next(), Some(i));
        }
    }
    
    #[test]
    fn test_session_id_generator_wrap() {
        let mut generator = SessionIdGenerator::new(SessionId::MAX - 1);
        assert_eq!(generator.next(), Some(SessionId::MAX - 1));
        assert_eq!(generator.next(), Some(SessionId::MAX));
        assert_eq!(generator.next(), None);
        generator.release(SessionId::MAX);
        assert_eq!(generator.next(), Some(SessionId::MAX));
        generator.release(SessionId::MAX - 1);
        assert_eq!(generator.next(), Some(SessionId::MAX - 1));
    }
    
    #[test]
    fn test_session_id_generator_release() {
        let mut generator = SessionIdGenerator::new(0);
        let id = generator.next().unwrap();
        generator.release(id);
        assert_eq!(generator.next(), Some(id));
    }
    
    #[test]
    fn test_session_id_generator_release_wrap() {
        let mut generator = SessionIdGenerator::new(SessionId::MAX - 1);
        let id = generator.next().unwrap();
        generator.release(id);
        assert_eq!(generator.next(), Some(id));
    }
}
