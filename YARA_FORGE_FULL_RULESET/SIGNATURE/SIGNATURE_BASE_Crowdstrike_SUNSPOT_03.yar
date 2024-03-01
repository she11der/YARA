rule SIGNATURE_BASE_Crowdstrike_SUNSPOT_03 : artifact logging stellarparticle sunspot STELLARPARTICLE FILE
{
	meta:
		description = "Detects log format lines in SUNSPOT"
		author = "(c) 2021 CrowdStrike Inc."
		id = "5535163e-a85a-587d-bb6e-083783f915c9"
		date = "2021-01-08"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_sunspot.yar#L45-L88"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ea701dc368af040e38fae8a076c96d95e167af70d5d71f3431184d20b0056373"
		score = 75
		quality = 83
		tags = "STELLARPARTICLE, FILE"
		version = "202101081443"
		actor = "StellarParticle"
		malware_family = "SUNSPOT"

	strings:
		$s01 = "[ERROR] ***Step1('%ls','%ls') fails with error %#x***\x0A" ascii
		$s02 = "[ERROR] Step2 fails\x0A" ascii
		$s03 = "[ERROR] Step3 fails\x0A" ascii
		$s04 = "[ERROR] Step4('%ls') fails\x0A" ascii
		$s05 = "[ERROR] Step5('%ls') fails\x0A" ascii
		$s06 = "[ERROR] Step6('%ls') fails\x0A" ascii
		$s07 = "[ERROR] Step7 fails\x0A" ascii
		$s08 = "[ERROR] Step8 fails\x0A" ascii
		$s09 = "[ERROR] Step9('%ls') fails\x0A" ascii
		$s10 = "[ERROR] Step10('%ls','%ls') fails with error %#x\x0A" ascii
		$s11 = "[ERROR] Step11('%ls') fails\x0A" ascii
		$s12 = "[ERROR] Step12('%ls','%ls') fails with error %#x\x0A" ascii
		$s13 = "[ERROR] Step30 fails\x0A" ascii
		$s14 = "[ERROR] Step14 fails with error %#x\x0A" ascii
		$s15 = "[ERROR] Step15 fails\x0A" ascii
		$s16 = "[ERROR] Step16 fails\x0A" ascii
		$s17 = "[%d] Step17 fails with error %#x\x0A" ascii
		$s18 = "[%d] Step18 fails with error %#x\x0A" ascii
		$s19 = "[ERROR] Step19 fails with error %#x\x0A" ascii
		$s20 = "[ERROR] Step20 fails\x0A" ascii
		$s21 = "[ERROR] Step21(%d,%s,%d) fails\x0A" ascii
		$s22 = "[ERROR] Step22 fails with error %#x\x0A" ascii
		$s23 = "[ERROR] Step23 fails with error %#x\x0A" ascii
		$s24 = "[%d] Solution directory: %ls\x0A" ascii
		$s25 = "[%d] %04d-%02d-%02d %02d:%02d:%02d:%03d %ls\x0A" ascii
		$s26 = "[%d] + '%s' " ascii

	condition:
		2 of them and filesize <10MB
}
