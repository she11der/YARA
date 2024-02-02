rule CRAIU_Apt_ZZ_Orangeworm_Kwampirs_Dropperandmainpayload___KWAMPIRS
{
	meta:
		description = "Kwampirs dropper and main payload components"
		author = "Symantec"
		id = "5a40a5e7-0b98-5f6e-a808-493676b57cda"
		date = "2018-04-23"
		modified = "2020-03-31"
		reference = "https://www.symantec.com/blogs/threat-intelligence/orangeworm-targets-healthcare-us-europe-asia"
		source_url = "https://github.com/craiu/yararules/blob/2b3716b6991652d91c8b89c39944611ade164aaa/files/apt_zz_orangeworm.yara#L2-L80"
		license_url = "https://github.com/craiu/yararules/blob/2b3716b6991652d91c8b89c39944611ade164aaa/LICENSE"
		logic_hash = "40e197f4278a2d14e8fe1359676558319e86728f7e61ddf612bcc894c311d53a"
		score = 75
		quality = 85
		tags = "KWAMPIRS"
		family = "Kwampirs"

	strings:
		$pubkey = {
            06 02 00 00 00 A4 00 00 52 53 41 31 00 08 00 00
            01 00 01 00 CD 74 15 BC 47 7E 0A 5E E4 35 22 A5
            97 0C 65 BE E0 33 22 F2 94 9D F5 40 97 3C 53 F9
            E4 7E DD 67 CF 5F 0A 5E F4 AD C9 CF 27 D3 E6 31
            48 B8 00 32 1D BE 87 10 89 DA 8B 2F 21 B4 5D 0A
            CD 43 D7 B4 75 C9 19 FE CC 88 4A 7B E9 1D 8C 11
            56 A6 A7 21 D8 C6 82 94 C1 66 11 08 E6 99 2C 33
            02 E2 3A 50 EA 58 D2 A7 36 EE 5A D6 8F 5D 5D D2
            9E 04 24 4A CE 4C B6 91 C0 7A C9 5C E7 5F 51 28
            4C 72 E1 60 AB 76 73 30 66 18 BE EC F3 99 5E 4B
            4F 59 F5 56 AD 65 75 2B 8F 14 0C 0D 27 97 12 71
            6B 49 08 84 61 1D 03 BA A5 42 92 F9 13 33 57 D9
            59 B3 E4 05 F9 12 23 08 B3 50 9A DA 6E 79 02 36
            EE CE 6D F3 7F 8B C9 BE 6A 7E BE 8F 85 B8 AA 82
            C6 1E 14 C6 1A 28 29 59 C2 22 71 44 52 05 E5 E6
            FE 58 80 6E D4 95 2D 57 CB 99 34 61 E9 E9 B3 3D
            90 DC 6C 26 5D 70 B4 78 F9 5E C9 7D 59 10 61 DF
            F7 E4 0C B3
}