//! Scoped decoder policy. Never changes process environment or hash workers.
use std::cell::Cell;
use std::marker::PhantomData;
use std::rc::Rc;

/// How an archive decodes compressed members.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum DecodeMode {
    /// Use the decoder's normal parallel selection and environment overrides.
    #[default]
    Auto,
    /// Adapt staged RAR5 batches to measured input and inline decode costs.
    /// Keeps the live dictionary; RAR4 and chunked extraction retain Auto behavior.
    Adaptive,
    /// Decode on the calling thread, including solid dictionary continuation.
    /// Hashing retains its independent execution policy.
    Serial,
}

thread_local! {
    static MODE: Cell<DecodeMode> = const { Cell::new(DecodeMode::Auto) };
}

pub(crate) fn serial() -> bool {
    MODE.get() == DecodeMode::Serial
}

pub(crate) fn adaptive() -> bool {
    MODE.get() == DecodeMode::Adaptive
}

pub(crate) struct Scope {
    previous: DecodeMode,
    // The policy must be restored on the same thread, even during unwinding.
    _thread: PhantomData<Rc<()>>,
}

impl DecodeMode {
    pub(crate) fn enter(self) -> Scope {
        // Reentrant callbacks may consume an independent archive with its own policy.
        let previous = MODE.replace(self);
        Scope {
            previous,
            _thread: PhantomData,
        }
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        MODE.set(self.previous);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_archives_install_their_own_mode_and_restore_the_caller() {
        for outer in [DecodeMode::Auto, DecodeMode::Adaptive, DecodeMode::Serial] {
            let _outer = outer.enter();
            for inner in [DecodeMode::Auto, DecodeMode::Adaptive, DecodeMode::Serial] {
                {
                    let _inner = inner.enter();
                    assert_eq!(MODE.get(), inner);
                }
                assert_eq!(MODE.get(), outer);
            }
        }
        assert_eq!(MODE.get(), DecodeMode::Auto);
    }

    #[test]
    fn serial_scope_is_nested_thread_local_and_unwind_safe() {
        assert!(!serial());
        let result = std::panic::catch_unwind(|| {
            let _serial = DecodeMode::Serial.enter();
            assert!(serial());
            {
                let _auto = DecodeMode::Auto.enter();
                assert!(!serial());
            }
            assert!(serial());
            assert!(!std::thread::spawn(serial).join().unwrap());
            panic!("exercise restoration");
        });
        assert!(result.is_err());
        assert!(!serial());
    }
}
