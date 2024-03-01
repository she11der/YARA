rule SIGNATURE_BASE_CN_Honker_Sig_3389_3389_3 : FILE
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file 3389.bat"
		author = "Florian Roth (Nextron Systems)"
		id = "ff61a5cb-6089-5632-a65d-09f4ffd99857"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_scripts.yar#L167-L183"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "cfedec7bd327897694f83501d76063fe16b13450"
		logic_hash = "df07958e44c7896bc7bdf2b79bc95969593eb21b9c9ed51213fd15affb731ec2"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "echo \"fDenyTSConnections\"=dword:00000000>>3389.reg " fullword ascii
		$s2 = "echo \"PortNumber\"=dword:00000d3d>>3389.reg " fullword ascii
		$s3 = "echo [HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server]>>" ascii

	condition:
		filesize <2KB and all of them
}
