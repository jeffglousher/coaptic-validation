//! Target-native decoded-view layouts; no workload or performance timing.
mod decoded_option_layout {
    use coaptic::message::{Header, OwnedToken, ParsedMessage, Token, TokenDecodeError, extended};

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
    struct TinyToken {
        bytes: [u8; 1],
        len: u8,
    }

    impl OwnedToken for TinyToken {
        const EMPTY: Self = Self { bytes: [0], len: 0 };
        const MAX_LEN: usize = 1;
        fn try_from_bytes(bytes: &[u8]) -> Result<Self, extended::CapacityError> {
            let mut token = Self::try_zeroed(bytes.len())?;
            token.as_bytes_mut().copy_from_slice(bytes);
            Ok(token)
        }
        fn try_zeroed(len: usize) -> Result<Self, extended::CapacityError> {
            if len > Self::MAX_LEN {
                return Err(extended::CapacityError {
                    required: len,
                    available: Self::MAX_LEN,
                });
            }
            Ok(Self {
                bytes: [0],
                len: len as u8,
            })
        }
        fn as_bytes_mut(&mut self) -> &mut [u8] {
            &mut self.bytes[..usize::from(self.len)]
        }
        fn as_bytes(&self) -> &[u8] {
            &self.bytes[..usize::from(self.len)]
        }
    }

    // Reproduce the baseline view's field types. This checks object layouts on
    // the actual test target; it is not a peak-stack or whole-App assertion.
    struct LegacyParsed<'a, T: OwnedToken> {
        _header: Header,
        _token: T,
        _options: &'a [u8],
        _payload: &'a [u8],
    }

    fn same_layout<T: OwnedToken>() {
        assert_eq!(
            core::mem::size_of::<ParsedMessage<'_, T>>(),
            core::mem::size_of::<LegacyParsed<'_, T>>(),
            "view size for {}",
            core::any::type_name::<T>()
        );
        assert_eq!(
            core::mem::align_of::<ParsedMessage<'_, T>>(),
            core::mem::align_of::<LegacyParsed<'_, T>>(),
            "view alignment for {}",
            core::any::type_name::<T>()
        );
        assert_eq!(
            core::mem::size_of::<Option<ParsedMessage<'_, T>>>(),
            core::mem::size_of::<Option<LegacyParsed<'_, T>>>(),
            "optional view size for {}",
            core::any::type_name::<T>()
        );
        assert_eq!(
            core::mem::size_of::<Result<ParsedMessage<'_, T>, TokenDecodeError>>(),
            core::mem::size_of::<Result<LegacyParsed<'_, T>, TokenDecodeError>>(),
            "decode result size for {}",
            core::any::type_name::<T>()
        );
        assert_eq!(
            core::mem::size_of::<Result<Option<ParsedMessage<'_, T>>, TokenDecodeError>>(),
            core::mem::size_of::<Result<Option<LegacyParsed<'_, T>>, TokenDecodeError>>(),
            "optional decode result size for {}",
            core::any::type_name::<T>()
        );
        assert_eq!(
            core::mem::size_of::<Option<Result<ParsedMessage<'_, T>, TokenDecodeError>>>(),
            core::mem::size_of::<Option<Result<LegacyParsed<'_, T>, TokenDecodeError>>>(),
            "nested decode result size for {}",
            core::any::type_name::<T>()
        );
    }

    #[test]
    fn compact_custom_and_extended_token_view_layouts_preserve_baseline_size() {
        assert_eq!(core::mem::size_of::<TinyToken>(), 2);
        assert_eq!(core::mem::size_of::<Header>(), 6);
        #[cfg(target_pointer_width = "64")]
        assert_eq!(core::mem::size_of::<ParsedMessage<'_, Token>>(), 48);
        same_layout::<Token>();
        same_layout::<TinyToken>();
        same_layout::<extended::Token<0>>();
        same_layout::<extended::Token<1>>();
        same_layout::<extended::Token<8>>();
        same_layout::<extended::Token<16>>();
        same_layout::<extended::Token<64>>();
        same_layout::<extended::Token<512>>();
    }
}
