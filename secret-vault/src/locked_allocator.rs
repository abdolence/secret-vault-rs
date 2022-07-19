use crate::allocator::{SecretVaultStoreValue, SecretVaultStoreValueAllocator};
use crate::encryption::EncryptedSecretValue;
use rvstruct::*;
use secret_vault_value::SecretValue;
use zeroize::Zeroize;

pub struct SecretVaultStoreValueLockMemAllocator;

impl SecretVaultStoreValueLockMemAllocator {
    pub fn new() -> Self {
        Self {}
    }
}

impl SecretVaultStoreValueAllocator for SecretVaultStoreValueLockMemAllocator {
    type R = SecretVaultStoreValueLockMemItem;

    fn allocate(
        &mut self,
        mut encrypted_secret: EncryptedSecretValue,
    ) -> SecretVaultStoreValue<Self::R> {
        let len = encrypted_secret.value().ref_sensitive_value().len();
        assert!(len > 0);
        let data = unsafe {
            let mut alloc = region::alloc(len, region::Protection::READ_WRITE).unwrap();
            let mut mut_ptr = alloc.as_mut_ptr::<u8>();
            mut_ptr.copy_from(encrypted_secret.value().ref_sensitive_value().as_ptr(), len);
            region::protect(mut_ptr, alloc.len(), region::Protection::READ).unwrap();
            let lock_guard = region::lock(mut_ptr, alloc.len()).unwrap();

            SecretVaultStoreValueLockMemItem {
                lock_guard: Some(lock_guard),
                alloc,
                data_len: len,
            }
        };
        SecretVaultStoreValue { data }
    }

    fn extract(&self, allocated: &SecretVaultStoreValue<Self::R>) -> EncryptedSecretValue {
        let mut src_data = Vec::with_capacity(allocated.data.data_len);
        unsafe {
            src_data.set_len(allocated.data.data_len);
            allocated
                .data
                .alloc
                .as_ptr::<u8>()
                .copy_to(src_data.as_mut_ptr(), allocated.data.data_len);
        }
        EncryptedSecretValue::from(SecretValue::new(src_data))
    }

    fn destroy(&mut self, value: SecretVaultStoreValue<Self::R>) {
        drop(value);
    }
}

pub struct SecretVaultStoreValueLockMemItem {
    lock_guard: Option<region::LockGuard>,
    alloc: region::Allocation,
    data_len: usize,
}

impl Drop for SecretVaultStoreValueLockMemItem {
    fn drop(&mut self) {
        unsafe {
            let mut alloc_mut_ptr = self.alloc.as_mut_ptr::<u8>();
            region::protect(
                alloc_mut_ptr,
                self.alloc.len(),
                region::Protection::READ_WRITE,
            )
            .unwrap();
            let uninit_slice = std::slice::from_raw_parts_mut(alloc_mut_ptr, self.alloc.len());
            uninit_slice.zeroize();
        }

        drop(self.lock_guard.take());
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;
    use secret_vault_value::SecretValue;

    fn generate_encrypted_secret_value() -> BoxedStrategy<EncryptedSecretValue> {
        ("[a-zA-Z0-9]+")
            .prop_map(|(mock_secret_str)| {
                EncryptedSecretValue::from(SecretValue::new(mock_secret_str.as_bytes().to_vec()))
            })
            .boxed()
    }

    proptest! {
        #[test]
        fn locks_secret_memory(mock_encrypted_secret_value in generate_encrypted_secret_value()) {
            let mut lock_allocator = SecretVaultStoreValueLockMemAllocator::new();
            let allocated = lock_allocator.allocate(mock_encrypted_secret_value.clone());
            let extracted = lock_allocator.extract(&allocated);
            lock_allocator.destroy(allocated);
            assert_eq!(extracted, mock_encrypted_secret_value);
        }
    }

    #[test]
    fn locks_secret_memory_64k() {
        let mut lock_allocator = SecretVaultStoreValueLockMemAllocator::new();

        for _i in 0..10 {
            let mock_encrypted_secret_value = EncryptedSecretValue::from(SecretValue::new(
                "42".repeat(32768).as_bytes().to_vec(),
            ));
            let allocated = lock_allocator.allocate(mock_encrypted_secret_value.clone());
            let extracted = lock_allocator.extract(&allocated);
            assert_eq!(extracted, mock_encrypted_secret_value);
        }
    }
}
