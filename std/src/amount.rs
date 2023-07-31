impl Display for Sats {
    /// Default formatting: decimal number of sats
    /// Dot notation: BTC.sats
    /// Alignment: add thousand separator (fill character)
    /// - left: 100'000.00'000'000
    /// - right: 100'000.000'000'00
    /// - center: 100'000.0000'0000
    /// Zero flag: prefix with zeros till 21'000'000
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let (btc, sats) = if let Some(precision) = f.precision() {
            let btc = match precision {
                0 => self.btc_round(),
                _ => self.btc_floor(),
            };
            let btc = match f.sign_aware_zero_pad() {
                true => format!("{:08}", btc),
                false => format!("{}", btc),
            };
            let sats = if precision > 0 {
                let sats = self.sats_rem();
                Some(format!("{}", sats))
            } else {
                None
            };
            (Some(btc), sats)
        } else {
            let sats = match f.sign_aware_zero_pad() {
                true => format!("{:08}", self.0),
                false => format!("{}", self.0),
            };
            (None, Some(sats))
        };

        let chunk = |mut iter: &str, first: usize, len: usize| -> Result<(), _> {
            if let Some((chunk, r)) = iter.split_once(iter.len() % first) {
                f.write_str(chunk)?;
                iter = r;
            }
            if iter.is_empty() {
                if f.align().is_some() {
                    f.write_char(f.fill())?;
                }
                while let Some((chunk, r)) = iter.split_once(len) {
                    f.write_str(chunk)?;
                    iter = r;
                }
            }
            Ok(())
        };
        if let Some(btc) = btc {
            chunk(&btc, 3, 3)?;
        }
        if let Some(sats) = sats {
            let (first, len) = match f.align() {
                None | Some(Alignment::Left) => 2,
                Some(Alignment::Right) => 3,
                Some(Alignment::Center) => 4,
            };
            chunk(&sats, first, len)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn sats_display() {
        assert_eq!(format!("{}", Sats(0)), "0");
        assert_eq!(format!("{}", Sats(1000)), "1000");
        assert_eq!(format!("{}", Sats::from_btc(1)), "100000000");
        assert_eq!(format!("{}", Sats::from_btc(1000)), "100000000000");

        assert_eq!(format!("{:.8}", Sats(0)), "0.00000000");
        assert_eq!(format!("{:.8}", Sats(1000)), "0.00001000");
        assert_eq!(format!("{:.8}", Sats::from_btc(1)), "1.00000000");
        assert_eq!(format!("{:.8}", Sats::from_btc(1000)), "1000.00000000");
    }
}
