rule SIGNATURE_BASE_APT30_Sample_8 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "5053c2db-32a9-58ae-9a72-eb16ef14168e"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt30_backspace.yar#L185-L201"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "9531e21652143b8b129ab8c023dc05fef2a17cc3"
		logic_hash = "bff21d517e97d2b13dff2b5ebc9a5b82b8f7635943c89f992b41d269623cd498"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "ateProcessA" ascii
		$s1 = "Ternel32.dllFQ" fullword ascii
		$s2 = "StartupInfoAModuleHand" fullword ascii
		$s3 = "OpenMutex" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
