rule SIGNATURE_BASE_RUAG_Bot_Config_File : FILE
{
	meta:
		description = "Detects a specific config file used by malware in RUAG APT case"
		author = "Florian Roth (Nextron Systems)"
		id = "aa3d5f9e-0b23-5180-9e52-a7d705712747"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://goo.gl/N5MEj0"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_ruag.yar#L21-L34"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "256808511233da446ec69db4f5a5e23a237296c100e79e78bbe5e4964fa5dde6"
		score = 60
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "[CONFIG]" ascii
		$s2 = "name = " ascii
		$s3 = "exe = cmd.exe" ascii

	condition:
		uint32(0)==0x4e4f435b and $s1 at 0 and $s2 and $s3 and filesize <160
}
