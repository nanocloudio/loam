// In-arena block-plane state machine. Tracks volumes + their
// allocation high-water marks. No actual block bytes here — those
// belong to the body provider or a block-device implementation.

#![allow(
    dead_code,
    reason = "shared #[path]-included surface; each includer uses a subset"
)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeSlot {
    pub volume_id_hash: u64,
    pub logical_bytes: u64,
    pub block_size: u32,
    pub allocated_blocks: u64,
    pub class: u8,
    pub thin_provisioned: bool,
    pub occupied: bool,
}

impl VolumeSlot {
    pub const fn empty() -> Self {
        Self {
            volume_id_hash: 0,
            logical_bytes: 0,
            block_size: 0,
            allocated_blocks: 0,
            class: 0,
            thin_provisioned: false,
            occupied: false,
        }
    }

    pub fn matches(&self, volume_id_hash: u64) -> bool {
        self.occupied && self.volume_id_hash == volume_id_hash
    }

    pub fn logical_block_count(&self) -> u64 {
        if self.block_size == 0 {
            0
        } else {
            self.logical_bytes / u64::from(self.block_size)
        }
    }

    pub fn free_blocks(&self) -> u64 {
        self.logical_block_count()
            .saturating_sub(self.allocated_blocks)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyError {
    AlreadyPresent,
    NotPresent,
    OutOfCapacity,
    AllocationExceedsVolume,
    ReleaseExceedsAllocated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOk {
    Created,
    Allocated { first_block: u64, count: u64 },
    Released { count: u64 },
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;

pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h = FNV_OFFSET;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

pub struct PicBlockState<const N: usize> {
    slots: [VolumeSlot; N],
}

impl<const N: usize> PicBlockState<N> {
    pub const fn new() -> Self {
        Self {
            slots: [VolumeSlot::empty(); N],
        }
    }

    pub const fn capacity(&self) -> usize {
        N
    }

    pub fn len(&self) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < N {
            if self.slots[i].occupied {
                n += 1;
            }
            i += 1;
        }
        n
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn lookup(&self, volume_id: &[u8]) -> Option<&VolumeSlot> {
        let h = fnv1a64(volume_id);
        for s in &self.slots {
            if s.matches(h) {
                return Some(s);
            }
        }
        None
    }

    pub fn create_volume(
        &mut self,
        volume_id: &[u8],
        class: u8,
        logical_bytes: u64,
        block_size: u32,
        thin_provisioned: bool,
    ) -> Result<ApplyOk, ApplyError> {
        let h = fnv1a64(volume_id);
        for s in &self.slots {
            if s.matches(h) {
                return Err(ApplyError::AlreadyPresent);
            }
        }
        for s in self.slots.iter_mut() {
            if !s.occupied {
                *s = VolumeSlot {
                    volume_id_hash: h,
                    logical_bytes,
                    block_size,
                    allocated_blocks: 0,
                    class,
                    thin_provisioned,
                    occupied: true,
                };
                return Ok(ApplyOk::Created);
            }
        }
        Err(ApplyError::OutOfCapacity)
    }

    pub fn allocate(&mut self, volume_id: &[u8], count: u64) -> Result<ApplyOk, ApplyError> {
        let h = fnv1a64(volume_id);
        for s in self.slots.iter_mut() {
            if s.matches(h) {
                if count > s.free_blocks() {
                    return Err(ApplyError::AllocationExceedsVolume);
                }
                let first = s.allocated_blocks;
                s.allocated_blocks = s.allocated_blocks.saturating_add(count);
                return Ok(ApplyOk::Allocated {
                    first_block: first,
                    count,
                });
            }
        }
        Err(ApplyError::NotPresent)
    }

    pub fn release(&mut self, volume_id: &[u8], count: u64) -> Result<ApplyOk, ApplyError> {
        let h = fnv1a64(volume_id);
        for s in self.slots.iter_mut() {
            if s.matches(h) {
                if count > s.allocated_blocks {
                    return Err(ApplyError::ReleaseExceedsAllocated);
                }
                s.allocated_blocks -= count;
                return Ok(ApplyOk::Released { count });
            }
        }
        Err(ApplyError::NotPresent)
    }
}

impl<const N: usize> Default for PicBlockState<N> {
    fn default() -> Self {
        Self::new()
    }
}
