rule SIGNATURE_BASE_Ping_Command_In_EXE : FILE
{
	meta:
		description = "Detects an suspicious ping command execution in an executable"
		author = "Florian Roth (Nextron Systems)"
		id = "937ab622-fbcf-5a31-a3ff-af2584484140"
		date = "2016-11-03"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_suspicious_strings.yar#L2-L15"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "1ea24774471eade7b7c50f0eae520e2b30dbec693e162b83ab0074465f179372"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "cmd /c ping 127.0.0.1 -n " ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
