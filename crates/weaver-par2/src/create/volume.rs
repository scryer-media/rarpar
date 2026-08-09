use crate::error::{Par2Error, Result};

const MAX_EXPLICIT_VOLUME_COUNT: u32 = 31;

/// A recovery-volume allocation before packet bytes are written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryVolumePlan {
    /// First recovery exponent assigned to this volume.
    pub first_exponent: u32,
    /// Number of recovery packets assigned to this volume.
    pub recovery_count: u32,
    /// Deterministic output filename for this volume.
    pub filename: String,
}

/// Divide recovery exponents into deterministic volume allocations.
pub(crate) fn allocate_volumes(
    first_exponent: u32,
    recovery_count: u32,
    requested_count: Option<u32>,
    scheme: super::options::VolumeScheme,
    stem: &str,
    largest_source_file_size: u64,
    block_size: u64,
) -> Result<Vec<RecoveryVolumePlan>> {
    if let Some(count) = requested_count {
        if count == 0 {
            return Err(Par2Error::InvalidCreationOptions {
                reason: "explicit volume count must be positive".to_string(),
            });
        }
        if count > MAX_EXPLICIT_VOLUME_COUNT {
            return Err(Par2Error::InvalidCreationOptions {
                reason: format!(
                    "explicit volume count {count} exceeds maximum {MAX_EXPLICIT_VOLUME_COUNT}"
                ),
            });
        }
    }
    if requested_count.is_some() && matches!(scheme, super::options::VolumeScheme::Limited) {
        return Err(Par2Error::InvalidCreationOptions {
            reason: "a volume count is not valid with limited volume sizing".to_string(),
        });
    }
    if recovery_count == 0 {
        if requested_count.is_some() {
            return Err(Par2Error::InvalidCreationOptions {
                reason: "a volume count is not valid when recovery count is zero".to_string(),
            });
        }
        return Ok(Vec::new());
    }

    let allocations = match (requested_count, scheme) {
        (Some(count), _) => uniform_allocations(first_exponent, recovery_count, count),
        (None, super::options::VolumeScheme::Uniform) => {
            let count = bit_length(recovery_count);
            uniform_allocations(first_exponent, recovery_count, count)
        }
        (None, super::options::VolumeScheme::Variable) => {
            let count = bit_length(recovery_count);
            variable_allocations(first_exponent, recovery_count, count)
        }
        (None, super::options::VolumeScheme::Limited) => limited_allocations(
            first_exponent,
            recovery_count,
            largest_source_file_size,
            block_size,
        )?,
    };
    let boundary_exponent = first_exponent.checked_add(recovery_count).ok_or_else(|| {
        Par2Error::InvalidCreationOptions {
            reason: "recovery exponent range overflows".to_string(),
        }
    })?;

    if allocations.is_empty() || allocations.len() as u32 > recovery_count {
        return Err(Par2Error::InvalidCreationOptions {
            reason: "recovery volumes must have a positive count".to_string(),
        });
    }
    let exponent = allocations
        .last()
        .and_then(|(first, count)| first.checked_add(*count))
        .ok_or_else(|| Par2Error::InvalidCreationOptions {
            reason: "recovery exponent range overflows".to_string(),
        })?;
    if exponent != boundary_exponent || allocations.iter().any(|(_, count)| *count == 0) {
        return Err(Par2Error::InvalidCreationOptions {
            reason: "recovery volume allocation does not cover the recovery range".to_string(),
        });
    }
    let exponent_width = decimal_width(boundary_exponent);
    let count_width = decimal_width(
        allocations
            .iter()
            .map(|&(_, count)| count)
            .chain(std::iter::once(0))
            .max()
            .unwrap_or(0),
    );
    let volumes = allocations
        .into_iter()
        .map(|(first_exponent, recovery_count)| RecoveryVolumePlan {
            filename: format!(
                "{stem}.vol{first_exponent:0exponent_width$}+{recovery_count:0count_width$}.par2"
            ),
            first_exponent,
            recovery_count,
        })
        .collect();
    Ok(volumes)
}

fn uniform_allocations(first_exponent: u32, total: u32, volume_count: u32) -> Vec<(u32, u32)> {
    let base = total / volume_count;
    let remainder = total % volume_count;
    let mut exponent = first_exponent;
    (0..volume_count)
        .map(|index| {
            let count = base + u32::from(index < remainder);
            let allocation = (exponent, count);
            exponent += count;
            allocation
        })
        .collect()
}

fn variable_allocations(first_exponent: u32, total: u32, volume_count: u32) -> Vec<(u32, u32)> {
    let mut low = 1u64;
    let geometric_sum = if volume_count >= 64 {
        u64::MAX
    } else {
        (1u64 << volume_count) - 1
    };
    while low.saturating_mul(geometric_sum) < total as u64 {
        low = low.saturating_mul(2);
    }

    let mut remaining = total as u64;
    let mut allocations = Vec::with_capacity(volume_count as usize);
    let mut exponent = first_exponent;
    for _ in 0..volume_count {
        let count = remaining.min(low);
        allocations.push((exponent, count as u32));
        exponent += count as u32;
        remaining -= count;
        low = low.saturating_mul(2);
    }
    allocations
}

fn limited_allocations(
    first_exponent: u32,
    recovery_count: u32,
    largest_source_file_size: u64,
    block_size: u64,
) -> Result<Vec<(u32, u32)>> {
    if block_size == 0 || largest_source_file_size == 0 {
        return Err(Par2Error::InvalidCreationOptions {
            reason: "limited volume sizing requires a non-empty source and block size".to_string(),
        });
    }
    let largest = u32::try_from(
        largest_source_file_size
            .checked_add(block_size - 1)
            .ok_or_else(|| Par2Error::InvalidCreationOptions {
                reason: "largest source block count overflows".to_string(),
            })?
            / block_size,
    )
    .map_err(|_| Par2Error::InvalidCreationOptions {
        reason: "largest source block count exceeds the supported range".to_string(),
    })?;
    if largest == 0 {
        return Err(Par2Error::InvalidCreationOptions {
            reason: "limited volume sizing computed zero source blocks".to_string(),
        });
    }

    let whole = recovery_count / largest;
    let whole = whole.saturating_sub(1);
    let extra = recovery_count - whole * largest;
    let volume_count =
        whole
            .checked_add(bit_length(extra))
            .ok_or_else(|| Par2Error::InvalidCreationOptions {
                reason: "limited volume count overflows".to_string(),
            })?;
    let mut allocations = vec![(0u32, 0u32); volume_count as usize];
    let mut filenumber = volume_count;
    let mut blocks = recovery_count;
    let mut exponent = first_exponent.checked_add(recovery_count).ok_or_else(|| {
        Par2Error::InvalidCreationOptions {
            reason: "recovery exponent range overflows".to_string(),
        }
    })?;

    while blocks >= largest.saturating_mul(2) && filenumber > 0 {
        filenumber -= 1;
        exponent -= largest;
        allocations[filenumber as usize] = (exponent, largest);
        blocks -= largest;
    }
    if filenumber == 0 || blocks == 0 {
        return Err(Par2Error::InvalidCreationOptions {
            reason: "limited volume allocation cannot place all recovery blocks".to_string(),
        });
    }

    exponent = first_exponent;
    let mut count = 1u32;
    for allocation in allocations.iter_mut().take(filenumber as usize) {
        let number = count.min(blocks);
        if number == 0 {
            return Err(Par2Error::InvalidCreationOptions {
                reason: "limited volume allocation produced an empty volume".to_string(),
            });
        }
        *allocation = (exponent, number);
        exponent += number;
        blocks -= number;
        count = count.saturating_mul(2);
    }
    if blocks != 0 {
        return Err(Par2Error::InvalidCreationOptions {
            reason: "limited volume allocation left recovery blocks unassigned".to_string(),
        });
    }
    Ok(allocations)
}

fn bit_length(value: u32) -> u32 {
    u32::BITS - value.leading_zeros()
}

fn decimal_width(value: u32) -> usize {
    value.to_string().len().max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create::options::VolumeScheme;

    #[test]
    fn automatic_count_is_bit_length() {
        let volumes = allocate_volumes(0, 5, None, VolumeScheme::Variable, "set", 20, 4).unwrap();
        assert_eq!(volumes.len(), 3);
        assert_eq!(
            volumes
                .iter()
                .map(|volume| volume.recovery_count)
                .sum::<u32>(),
            5
        );
    }

    #[test]
    fn uniform_allocation_and_widths_are_stable() {
        let volumes =
            allocate_volumes(7, 10, Some(3), VolumeScheme::Uniform, "set", 20, 4).unwrap();
        assert_eq!(
            volumes
                .iter()
                .map(|volume| volume.recovery_count)
                .collect::<Vec<_>>(),
            vec![4, 3, 3]
        );
        assert_eq!(volumes[0].filename, "set.vol07+4.par2");
        assert_eq!(volumes[2].first_exponent, 14);
    }

    #[test]
    fn widths_include_the_zero_count_boundary_entry() {
        let volumes =
            allocate_volumes(0, 100, Some(3), VolumeScheme::Uniform, "set", 400, 4).unwrap();
        assert_eq!(volumes[0].filename, "set.vol000+34.par2");
        assert_eq!(volumes[2].filename, "set.vol067+33.par2");
    }

    #[test]
    fn explicit_count_forces_uniform_allocation() {
        let volumes =
            allocate_volumes(0, 100, Some(10), VolumeScheme::Variable, "set", 400, 4).unwrap();
        assert_eq!(
            volumes
                .iter()
                .map(|volume| volume.recovery_count)
                .collect::<Vec<_>>(),
            vec![10; 10]
        );
        assert_eq!(volumes[0].filename, "set.vol000+10.par2");
        assert_eq!(volumes[9].filename, "set.vol090+10.par2");
    }

    #[test]
    fn explicit_count_above_public_limit_is_rejected() {
        let error =
            allocate_volumes(0, 100, Some(32), VolumeScheme::Uniform, "set", 400, 4).unwrap_err();
        assert!(matches!(error, Par2Error::InvalidCreationOptions { .. }));
    }

    #[test]
    fn limited_allocation_matches_largest_source_cap() {
        for (recovery_count, expected) in [
            (1, vec![1]),
            (10, vec![1, 2, 4, 3]),
            (20, vec![1, 2, 4, 3, 10]),
            (35, vec![1, 2, 4, 8, 10, 10]),
        ] {
            let volumes =
                allocate_volumes(0, recovery_count, None, VolumeScheme::Limited, "set", 40, 4)
                    .unwrap();
            assert_eq!(
                volumes
                    .iter()
                    .map(|volume| volume.recovery_count)
                    .collect::<Vec<_>>(),
                expected
            );
            assert!(volumes.iter().all(|volume| volume.recovery_count <= 10));
        }

        let volumes = allocate_volumes(7, 20, None, VolumeScheme::Limited, "set", 40, 4).unwrap();
        assert_eq!(volumes[0].filename, "set.vol07+01.par2");
        assert_eq!(volumes.last().unwrap().filename, "set.vol17+10.par2");
    }

    #[test]
    fn limited_allocation_rejects_explicit_count() {
        let error =
            allocate_volumes(0, 8, Some(2), VolumeScheme::Limited, "set", 40, 4).unwrap_err();
        assert!(matches!(error, Par2Error::InvalidCreationOptions { .. }));
    }
}
