rule SIGNATURE_BASE_Gen_Net_Localgroup_Administrators_Add_Command : FILE
{
	meta:
		description = "Detects an executable that contains a command to add a user account to the local administrators group"
		author = "Florian Roth (Nextron Systems)"
		id = "9f6095fc-6d9f-5814-b407-f320191fd912"
		date = "2017-07-08"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_suspicious_strings.yar#L34-L46"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "af4d7c8586022583e2019bbdc3638704e1d237b25e3c214f3bc2db64c58c8bd3"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = /net localgroup administrators [a-zA-Z0-9]{1,16} \/add/ nocase ascii

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and 1 of them )
}
