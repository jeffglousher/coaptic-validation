//! Rotating occupancy used by every pool and table.
//!
//! Acquire starts at the cursor and wraps. A successful acquire leaves the cursor
//! on the following index so the next pass does not restart at zero.
//!
//! [`Occupancy::occupied_count`] is a live counter (increment acquire,
//! decrement release) so idle [`super::Engine::progress`] can skip empty
//! tables in O(1). Datagram and body pools pin an occupied slot while
//! [`super::Access`] is live. [`release`] returns [`SlotError::Pinned`]
//! for that id. Rotate does not evict, so it does not consult the pin bit.

use super::slot::{SlotError, SlotId};

pub(crate) fn acquire(
    occupied: &mut [bool],
    pinned: &mut [bool],
    cursor: &mut usize,
) -> Option<SlotId> {
    let n = occupied.len();
    if n == 0 {
        return None;
    }
    for offset in 0..n {
        let idx = (*cursor + offset) % n;
        if !occupied[idx] {
            occupied[idx] = true;
            if let Some(pin) = pinned.get_mut(idx) {
                *pin = false;
            }
            *cursor = (idx + 1) % n;
            return Some(SlotId::from_index(idx));
        }
    }
    None
}

pub(crate) fn release(occupied: &mut [bool], pinned: &[bool], id: SlotId) -> Result<(), SlotError> {
    let Some(slot) = occupied.get_mut(id.index()) else {
        return Err(SlotError::InvalidSlot);
    };
    if !*slot {
        return Err(SlotError::NotOccupied);
    }
    if pinned.get(id.index()).copied().unwrap_or(false) {
        return Err(SlotError::Pinned);
    }
    *slot = false;
    Ok(())
}

pub(crate) fn try_pin(occupied: &[bool], pinned: &mut [bool], id: SlotId) -> Result<(), SlotError> {
    let Some(&occ) = occupied.get(id.index()) else {
        return Err(SlotError::InvalidSlot);
    };
    if !occ {
        return Err(SlotError::NotOccupied);
    }
    let pin = pinned.get_mut(id.index()).ok_or(SlotError::InvalidSlot)?;
    if *pin {
        return Err(SlotError::Pinned);
    }
    *pin = true;
    Ok(())
}

#[cfg(test)]
pub(crate) fn unpin(pinned: &mut [bool], id: SlotId) -> Result<(), SlotError> {
    let pin = pinned.get_mut(id.index()).ok_or(SlotError::InvalidSlot)?;
    *pin = false;
    Ok(())
}

pub(crate) fn is_pinned(pinned: &[bool], id: SlotId) -> bool {
    pinned.get(id.index()).copied().unwrap_or(false)
}

#[cfg(feature = "alloc")]
pub(crate) fn advance(cursor: &mut usize, n: usize, steps: usize) {
    if n == 0 {
        return;
    }
    *cursor = (*cursor + (steps % n)) % n;
}

pub(crate) fn occupied_count(occupied: &[bool]) -> usize {
    occupied.iter().filter(|occupied| **occupied).count()
}

pub(crate) fn is_occupied(occupied: &[bool], id: SlotId) -> bool {
    occupied.get(id.index()).copied().unwrap_or(false)
}

/// Compile-time occupancy flags plus a rotating cursor.
pub(crate) struct Occupancy<const N: usize> {
    occupied: [bool; N],
    pinned: [bool; N],
    cursor: usize,
    count: usize,
}

impl<const N: usize> Occupancy<N> {
    pub(crate) const fn new() -> Self {
        Self {
            occupied: [false; N],
            pinned: [false; N],
            cursor: 0,
            count: 0,
        }
    }

    pub(crate) fn acquire(&mut self) -> Option<SlotId> {
        if self.count == N {
            return None;
        }
        let id = acquire(&mut self.occupied, &mut self.pinned, &mut self.cursor)?;
        self.count += 1;
        debug_assert_eq!(self.count, occupied_count(&self.occupied));
        Some(id)
    }

    pub(crate) fn release(&mut self, id: SlotId) -> Result<(), SlotError> {
        release(&mut self.occupied, &self.pinned, id)?;
        self.count -= 1;
        debug_assert_eq!(self.count, occupied_count(&self.occupied));
        Ok(())
    }

    pub(crate) fn try_pin(&mut self, id: SlotId) -> Result<(), SlotError> {
        try_pin(&self.occupied, &mut self.pinned, id)
    }

    #[cfg(test)]
    pub(crate) fn unpin(&mut self, id: SlotId) -> Result<(), SlotError> {
        unpin(&mut self.pinned, id)
    }

    pub(crate) fn pin_flag_mut(&mut self, id: SlotId) -> Option<&mut bool> {
        self.pinned.get_mut(id.index())
    }

    pub(crate) fn is_pinned(&self, id: SlotId) -> bool {
        is_pinned(&self.pinned, id)
    }

    #[cfg(test)]
    pub(crate) fn rotate(&mut self) {
        self.advance(1);
    }

    pub(crate) fn advance(&mut self, steps: usize) {
        if N == 0 {
            return;
        }
        self.set_cursor(self.cursor + (steps % N));
    }

    pub(crate) fn set_cursor(&mut self, cursor: usize) {
        if N == 0 {
            return;
        }
        self.cursor = cursor % N;
    }

    pub(crate) const fn slot_count(&self) -> usize {
        N
    }

    pub(crate) const fn occupied_count(&self) -> usize {
        self.count
    }

    pub(crate) fn is_occupied(&self, id: SlotId) -> bool {
        is_occupied(&self.occupied, id)
    }

    pub(crate) const fn cursor(&self) -> usize {
        self.cursor
    }
}

/// Runtime occupancy for the `alloc` backend. Flags are allocated once.
#[cfg(feature = "alloc")]
pub(crate) struct HeapOccupancy {
    occupied: alloc::boxed::Box<[bool]>,
    pinned: alloc::boxed::Box<[bool]>,
    cursor: usize,
    count: usize,
}

#[cfg(feature = "alloc")]
impl HeapOccupancy {
    pub(crate) fn new(n: usize) -> Self {
        Self {
            occupied: alloc::vec![false; n].into_boxed_slice(),
            pinned: alloc::vec![false; n].into_boxed_slice(),
            cursor: 0,
            count: 0,
        }
    }

    pub(crate) fn acquire(&mut self) -> Option<SlotId> {
        if self.count == self.occupied.len() {
            return None;
        }
        let id = acquire(&mut self.occupied, &mut self.pinned, &mut self.cursor)?;
        self.count += 1;
        debug_assert_eq!(self.count, occupied_count(&self.occupied));
        Some(id)
    }

    pub(crate) fn release(&mut self, id: SlotId) -> Result<(), SlotError> {
        release(&mut self.occupied, &self.pinned, id)?;
        self.count -= 1;
        debug_assert_eq!(self.count, occupied_count(&self.occupied));
        Ok(())
    }

    pub(crate) fn try_pin(&mut self, id: SlotId) -> Result<(), SlotError> {
        try_pin(&self.occupied, &mut self.pinned, id)
    }

    pub(crate) fn pin_flag_mut(&mut self, id: SlotId) -> Option<&mut bool> {
        self.pinned.get_mut(id.index())
    }

    pub(crate) fn is_pinned(&self, id: SlotId) -> bool {
        is_pinned(&self.pinned, id)
    }

    pub(crate) fn advance(&mut self, steps: usize) {
        advance(&mut self.cursor, self.occupied.len(), steps);
    }

    pub(crate) fn slot_count(&self) -> usize {
        self.occupied.len()
    }

    pub(crate) fn occupied_count(&self) -> usize {
        self.count
    }

    pub(crate) fn is_occupied(&self, id: SlotId) -> bool {
        is_occupied(&self.occupied, id)
    }

    pub(crate) fn cursor(&self) -> usize {
        self.cursor
    }
}

#[cfg(test)]
mod tests {
    use super::Occupancy;
    use crate::storage::SlotError;
    use crate::storage::SlotId;

    #[test]
    fn pin_refuses_release() {
        let mut occ = Occupancy::<2>::new();
        let id = occ.acquire().expect("acquire");
        occ.try_pin(id).expect("pin");
        assert!(occ.is_pinned(id));
        assert_eq!(occ.release(id), Err(SlotError::Pinned));
        assert!(occ.is_occupied(id));
        occ.unpin(id).expect("unpin");
        assert!(!occ.is_pinned(id));
        occ.release(id).expect("release after unpin");
        assert!(!occ.is_occupied(id));
    }

    #[test]
    fn drop_style_unpin_allows_release() {
        let mut occ = Occupancy::<1>::new();
        let id = occ.acquire().expect("acquire");
        occ.try_pin(id).expect("pin");
        *occ.pin_flag_mut(id).expect("flag") = false;
        occ.release(id).expect("release after flag clear");
    }

    #[test]
    fn double_pin_is_exclusive() {
        let mut occ = Occupancy::<2>::new();
        let id = occ.acquire().expect("acquire");
        occ.try_pin(id).expect("first pin");
        assert_eq!(occ.try_pin(id), Err(SlotError::Pinned));
        occ.unpin(id).expect("unpin");
        occ.try_pin(id).expect("pin after unpin");
    }

    #[test]
    fn pin_requires_occupied() {
        let mut occ = Occupancy::<2>::new();
        let id = SlotId::from_index(0);
        assert_eq!(occ.try_pin(id), Err(SlotError::NotOccupied));
        assert_eq!(
            occ.try_pin(SlotId::from_index(4)),
            Err(SlotError::InvalidSlot)
        );
    }

    #[test]
    fn rotate_does_not_evict_pinned() {
        let mut occ = Occupancy::<2>::new();
        let id = occ.acquire().expect("acquire");
        occ.try_pin(id).expect("pin");
        let cursor = occ.cursor();
        occ.rotate();
        assert_ne!(occ.cursor(), cursor);
        assert!(occ.is_occupied(id));
        assert!(occ.is_pinned(id));
        assert_eq!(occ.release(id), Err(SlotError::Pinned));
    }

    #[test]
    fn advance_jumps_cursor_in_one_modulo() {
        let mut occ = Occupancy::<4>::new();
        occ.advance(3);
        assert_eq!(occ.cursor(), 3);
        occ.advance(2);
        assert_eq!(occ.cursor(), 1);
        occ.set_cursor(5);
        assert_eq!(occ.cursor(), 1);
        occ.advance(0);
        assert_eq!(occ.cursor(), 1);
    }

    #[test]
    fn occupied_count_tracks_acquire_release() {
        let mut occ = Occupancy::<2>::new();
        assert_eq!(occ.occupied_count(), 0);
        let a = occ.acquire().expect("a");
        assert_eq!(occ.occupied_count(), 1);
        let b = occ.acquire().expect("b");
        assert_eq!(occ.occupied_count(), 2);
        assert!(occ.acquire().is_none());
        assert_eq!(occ.occupied_count(), 2);
        occ.release(a).expect("release a");
        assert_eq!(occ.occupied_count(), 1);
        occ.release(b).expect("release b");
        assert_eq!(occ.occupied_count(), 0);
        assert_eq!(occ.release(a), Err(SlotError::NotOccupied));
        assert_eq!(occ.occupied_count(), 0);
    }

    #[test]
    fn occupied_count_unchanged_while_pinned() {
        let mut occ = Occupancy::<1>::new();
        let id = occ.acquire().expect("acquire");
        occ.try_pin(id).expect("pin");
        assert_eq!(occ.release(id), Err(SlotError::Pinned));
        assert_eq!(occ.occupied_count(), 1);
        occ.unpin(id).expect("unpin");
        occ.release(id).expect("release");
        assert_eq!(occ.occupied_count(), 0);
    }
}
