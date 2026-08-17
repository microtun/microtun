use embassy_stm32::{
    Peri,
    adc::{Adc, SampleTime, Temperature, VrefInt},
    pac,
    peripherals::ADC3,
};

const TS_CAL1_ADDRESS: usize = 0x1ff1_e820;
const TS_CAL2_ADDRESS: usize = 0x1ff1_e840;
const VREFINT_CAL_ADDRESS: usize = 0x1ff1_e860;
const TS_CAL1_MILLICELSIUS: i64 = 30_000;
const STM32H7_REV_Y_MAX: u16 = 0x1003;

#[derive(Clone, Copy)]
struct TemperatureCalibration {
    ts_cal1: u16,
    ts_cal2: u16,
    ts_cal2_millicelsius: i64,
    vrefint_cal: u16,
}

impl TemperatureCalibration {
    fn read() -> Self {
        Self {
            // The STM32H753 factory calibration words live in system memory.
            // embassy-stm32 0.6.0's H753 PAC does not expose these three
            // words, so keep the documented addresses isolated here rather
            // than leaking raw pointers into the ADC/conversion code.
            ts_cal1: read_factory_calibration_word(TS_CAL1_ADDRESS),
            ts_cal2: read_factory_calibration_word(TS_CAL2_ADDRESS),
            ts_cal2_millicelsius: stm32_ts_cal2_millicelsius(),
            vrefint_cal: read_factory_calibration_word(VREFINT_CAL_ADDRESS),
        }
    }

    fn convert_millicelsius(self, raw_temp: u32, raw_vref: u32) -> Option<i32> {
        // Both factory temperature points are taken at VDDA=3.3 V. Correct
        // the live temperature sample back to that calibration voltage using
        // the factory VREFINT calibration value before interpolating.
        if raw_vref == 0 || self.vrefint_cal == 0 || self.ts_cal2 <= self.ts_cal1 {
            return None;
        }

        let compensated = raw_temp.saturating_mul(u32::from(self.vrefint_cal)) / raw_vref;
        let cal1 = i64::from(self.ts_cal1);
        let cal2 = i64::from(self.ts_cal2);
        let temperature = TS_CAL1_MILLICELSIUS
            + (i64::from(compensated) - cal1) * (self.ts_cal2_millicelsius - TS_CAL1_MILLICELSIUS)
                / (cal2 - cal1);

        Some(temperature.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32)
    }
}

pub(crate) struct TemperatureSensor {
    adc: Adc<'static, ADC3>,
    temperature: Temperature,
    vrefint: VrefInt,
    calibration: TemperatureCalibration,
}

impl TemperatureSensor {
    pub(crate) fn new(adc3: Peri<'static, ADC3>) -> Self {
        let adc = Adc::new(adc3);
        let temperature = adc.enable_temperature();
        let vrefint = adc.enable_vrefint();

        Self {
            adc,
            temperature,
            vrefint,
            calibration: TemperatureCalibration::read(),
        }
    }

    pub(crate) fn read_millicelsius(&mut self) -> Option<i32> {
        // The H753 datasheet requires at least 9 us of sampling time for the
        // internal temperature channel. 810.5 ADC cycles is deliberately
        // conservative and this command is interactive, not a hot path.
        let raw_temp = u32::from(
            self.adc
                .blocking_read(&mut self.temperature, SampleTime::CYCLES810_5),
        );
        let raw_vref = u32::from(
            self.adc
                .blocking_read(&mut self.vrefint, SampleTime::CYCLES810_5),
        );

        self.calibration.convert_millicelsius(raw_temp, raw_vref)
    }
}

fn read_factory_calibration_word(address: usize) -> u16 {
    // These addresses are documented by ST as read-only factory calibration
    // words in STM32H753 system memory. Keep the unsafe MMIO read in one
    // helper so the rest of the temperature path stays typed and testable.
    unsafe { core::ptr::read_volatile(address as *const u16) }
}

fn stm32_ts_cal2_millicelsius() -> i64 {
    // ST calibrates TS_CAL2 at 110 C on revision Y silicon and 130 C on
    // revision V. Their H7 LL driver uses REV_ID <= 0x1003 for the revision-Y
    // case on STM32H742/H743/H750/H753.
    if pac::DBGMCU.idc().read().rev_id() <= STM32H7_REV_Y_MAX {
        110_000
    } else {
        130_000
    }
}
