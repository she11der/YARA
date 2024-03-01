rule SIGNATURE_BASE_Lightftp_Config : FILE
{
	meta:
		description = "Detects a light FTP server - config file"
		author = "Florian Roth (Nextron Systems)"
		id = "02ee1d04-1425-5dfd-9b9a-cd378aeda311"
		date = "2015-05-14"
		modified = "2023-12-05"
		reference = "https://github.com/hfiref0x/LightFTP"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/pup_lightftp.yar#L23-L41"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "ce9821213538d39775af4a48550eefa3908323c5"
		logic_hash = "1e8c06dac9a5910816703ed15bef83116d9e2d9e612fda69697170ed98ee5f60"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "maxusers=" wide
		$s6 = "[ftpconfig]" fullword wide
		$s8 = "accs=readonly" fullword wide
		$s9 = "[anonymous]" fullword wide
		$s10 = "accs=" fullword wide
		$s11 = "pswd=" fullword wide

	condition:
		uint16(0)==0xfeff and filesize <1KB and all of them
}
