rule SIGNATURE_BASE_Binary_Drop_Certutil : FILE
{
	meta:
		description = "Drop binary as base64 encoded cert trick"
		author = "Florian Roth (Nextron Systems)"
		id = "19791e51-d041-524d-80fa-9f3ec54eb084"
		date = "2015-07-15"
		modified = "2023-12-05"
		reference = "https://goo.gl/9DNn8q"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/general_cloaking.yar#L92-L107"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "3e2b62442b5da6ab887e1eb03cdd44932651fa51ce11e87e6fc29015e708d2f3"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "echo -----BEGIN CERTIFICATE----- >" ascii
		$s1 = "echo -----END CERTIFICATE----- >>" ascii
		$s2 = "certutil -decode " ascii

	condition:
		filesize <10KB and all of them
}
