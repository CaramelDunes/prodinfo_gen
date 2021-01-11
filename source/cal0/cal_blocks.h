#ifndef CAL_BLOCKS_H
#define CAL_BLOCKS_H

typedef unsigned char u8;
typedef unsigned short int u16;

typedef struct crc_block
{
    const char *name;
    const u16 offset;
    const u16 size;
} crc_block_t;

#define CRC_BLOCK(name, offset, size) \
    static const crc_block_t name##_block = {#name, offset, size}

#define SHA256_BLOCK(name, offset, size) \
    static const crc_block_t name##_block = {#name, offset, size}

#define OFFSET_OF_BLOCK(name) (name##_block.offset)
#define SIZE_OF_BLOCK(name) (name##_block.size)
#define BLOCK_OF(name) name##_block

#define CAL_SIZE 0x8000

CRC_BLOCK(ConfigurationId1, 0x40, 0x20); // DEFAULT MP_00_01_00_00

CRC_BLOCK(WlanCountryCodes, 0x80, 0x190); // DEFAULT

CRC_BLOCK(WlanMacAddress, 0x210, 0x08);
CRC_BLOCK(BtMacAddress, 0x220, 0x08);

CRC_BLOCK(AccelerometerOffset, 0x230, 0x08); // DEFAULT
CRC_BLOCK(AccelerometerScale, 0x238, 0x08);  // DEFAULT FF 3F FF 3F FF 3F
CRC_BLOCK(GyroscopeOffset, 0x240, 0x08);
CRC_BLOCK(GyroscopeScale, 0x248, 0x08);
CRC_BLOCK(SerialNumber, 0x250, 0x20);

CRC_BLOCK(EccP256DeviceKey, 0x0270, 0x40);          // EMPTY
CRC_BLOCK(EccP256DeviceCertificate, 0x02B0, 0x190); // EMPTY
CRC_BLOCK(EccB233DeviceKey, 0x0440, 0x40);          // EMPTY

CRC_BLOCK(EccB233DeviceCertificate, 0x0480, 0x190);

CRC_BLOCK(EccP256ETicketKey, 0x0610, 0x40);          // EMPTY
CRC_BLOCK(EccP256ETicketCertificate, 0x0650, 0x190); // EMPTY
CRC_BLOCK(EccB233ETicketKey, 0x07E0, 0x40);          // EMPTY
CRC_BLOCK(EccB233ETicketCertificate, 0x0820, 0x190); // EMPTY

CRC_BLOCK(SslKey, 0x09B0, 0x120); // EMPTY
CRC_BLOCK(SslCertificateSize, 0x0AD0, 0x10);

CRC_BLOCK(GameCardKey, 0x2320, 0x120); // EMPTY

CRC_BLOCK(Rsa2048ETicketKey, 0x2860, 0x230); // EMPTY
CRC_BLOCK(Rsa2048ETicketCertificate, 0x2A90, 0x250);

CRC_BLOCK(BatteryLot, 0x2CE0, 0x20);
CRC_BLOCK(SpeakerCalibrationValue, 0x2D00, 0x810);

CRC_BLOCK(RegionCode, 0x3510, 0x10); // DEFAULT 1

CRC_BLOCK(AmiiboKey, 0x3520, 0x60);
CRC_BLOCK(AmiiboEcqvCertificate, 0x3580, 0x20);
CRC_BLOCK(AmiiboEcdsaCertificate, 0x35A0, 0x80);
CRC_BLOCK(AmiiboEcqvBlsKey, 0x3620, 0x50);
CRC_BLOCK(AmiiboEcqvBlsCertificate, 0x3670, 0x30);
CRC_BLOCK(AmiiboEcqvBlsRootCertificate, 0x36A0, 0xA0);

CRC_BLOCK(ProductModel, 0x3740, 0x10);                     // DEFAULT Nx = 1
CRC_BLOCK(HomeMenuSchemeMainColorVariation, 0x3750, 0x10); // DEFAULT 0
CRC_BLOCK(LcdBacklightBrightnessMapping, 0x3760, 0x10);    // DEFAULT 00 00 80 3F 00 00 00 00 0A D7 A3 3C

CRC_BLOCK(ExtendedEccB233DeviceKey, 0x3770, 0x60);
CRC_BLOCK(ExtendedEccP256ETicketKey, 0x37D0, 0x60); // EMPTY
CRC_BLOCK(ExtendedEccB233ETicketKey, 0x3830, 0x60); // EMPTY
CRC_BLOCK(ExtendedRsa2048ETicketKey, 0x3890, 0x250);
CRC_BLOCK(ExtendedSslKey, 0x3AE0, 0x140);
CRC_BLOCK(ExtendedGameCardKey, 0x3C20, 0x140);
CRC_BLOCK(LcdVendorId, 0x3D60, 0x10);

CRC_BLOCK(ExtendedRsa2048DeviceKey, 0x3D70, 0x250); // If the CRC value of this is valid, HOS will try to use it and may hang.
CRC_BLOCK(Rsa2048DeviceCertificate, 0x3FC0, 0x250);

CRC_BLOCK(UsbTypeCPowerSourceCircuitVersion, 0x4210, 0x10);

CRC_BLOCK(HousingSubColor, 0x4220, 0x10);
CRC_BLOCK(HousingBezelColor, 0x4230, 0x10);
CRC_BLOCK(HousingMainColor1, 0x4240, 0x10);
CRC_BLOCK(HousingMainColor2, 0x4250, 0x10);
CRC_BLOCK(HousingMainColor3, 0x4260, 0x10);

CRC_BLOCK(AnalogStickModuleTypeL, 0x4270, 0x10);
CRC_BLOCK(AnalogStickModelParameterL, 0x4280, 0x20);
CRC_BLOCK(AnalogStickFactoryCalibrationL, 0x42A0, 0x10);

CRC_BLOCK(AnalogStickModuleTypeR, 0x42B0, 0x10);
CRC_BLOCK(AnalogStickModelParameterR, 0x42C0, 0x20);
CRC_BLOCK(AnalogStickFactoryCalibrationR, 0x42E0, 0x10);

CRC_BLOCK(ConsoleSixAxisSensorModuleType, 0x42F0, 0x10);
CRC_BLOCK(ConsoleSixAxisSensorHorizontalOffset, 0x4300, 0x10);

CRC_BLOCK(BatteryVersion, 0x4310, 0x10);
CRC_BLOCK(TouchIcVendorId, 0x4320, 0x10);
CRC_BLOCK(ColorModel, 0x4330, 0x10);
CRC_BLOCK(ConsoleSixAxisSensorMountType, 0x4340, 0x10);

static const crc_block_t crc_blocks[] = {
    BLOCK_OF(ConfigurationId1), // DEFAULT MP_00_01_00_00

    BLOCK_OF(WlanCountryCodes), // DEFAULT

    BLOCK_OF(WlanMacAddress),
    BLOCK_OF(BtMacAddress),

    BLOCK_OF(AccelerometerOffset),
    BLOCK_OF(AccelerometerScale),
    BLOCK_OF(GyroscopeOffset),
    BLOCK_OF(GyroscopeScale),
    BLOCK_OF(SerialNumber),

    BLOCK_OF(EccP256DeviceKey),
    BLOCK_OF(EccP256DeviceCertificate),
    BLOCK_OF(EccB233DeviceKey),

    BLOCK_OF(EccB233DeviceCertificate),

    BLOCK_OF(EccP256ETicketKey),
    BLOCK_OF(EccP256ETicketCertificate),
    BLOCK_OF(EccB233ETicketKey),
    BLOCK_OF(EccB233ETicketCertificate),

    BLOCK_OF(SslKey),
    BLOCK_OF(SslCertificateSize),

    BLOCK_OF(GameCardKey),

    BLOCK_OF(Rsa2048ETicketKey),
    BLOCK_OF(Rsa2048ETicketCertificate),

    BLOCK_OF(BatteryLot),
    BLOCK_OF(SpeakerCalibrationValue),

    BLOCK_OF(RegionCode),

    BLOCK_OF(AmiiboKey),
    BLOCK_OF(AmiiboEcqvCertificate),
    BLOCK_OF(AmiiboEcdsaCertificate),
    BLOCK_OF(AmiiboEcqvBlsKey),
    BLOCK_OF(AmiiboEcqvBlsCertificate),
    BLOCK_OF(AmiiboEcqvBlsRootCertificate),

    BLOCK_OF(ProductModel),
    BLOCK_OF(HomeMenuSchemeMainColorVariation),
    BLOCK_OF(LcdBacklightBrightnessMapping),

    BLOCK_OF(ExtendedEccB233DeviceKey),
    BLOCK_OF(ExtendedEccP256ETicketKey),
    BLOCK_OF(ExtendedEccB233ETicketKey),
    BLOCK_OF(ExtendedRsa2048ETicketKey),
    BLOCK_OF(ExtendedSslKey),
    BLOCK_OF(ExtendedGameCardKey),
    BLOCK_OF(LcdVendorId)};

SHA256_BLOCK(SslCertificate, 0x0AE0, 0x820); // WARNING, ONLY USE Size bytes to compute hash
SHA256_BLOCK(RandomNumber, 0x1300, 0x1020);
SHA256_BLOCK(GameCardCertificate, 0x2440, 0x420);

#endif