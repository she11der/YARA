rule SIGNATURE_BASE_HKTL_Redmimicry_Agent
{
	meta:
		description = "matches the RedMimicry agent executable and payload"
		author = "mirar@chaosmail.org"
		id = "a4d4ec77-4a0d-5afd-9181-85433e8b5fda"
		date = "2020-06-22"
		modified = "2023-01-06"
		reference = "https://redmimicry.com"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_redmimicry.yar#L2-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "645da2764ca911c4aae80b90622d2c61933dee929403858fc49f7bc0d44300c6"
		score = 75
		quality = 85
		tags = ""
		sharing = "tlp:white"

	strings:
		$reg0 = "HKEY_CURRENT_USER\\" ascii
		$reg1 = "HKEY_LOCAL_MACHINE\\" ascii
		$reg2 = "HKEY_CURRENT_CONFIG\\" ascii
		$reg3 = "HKEY_CLASSES_ROOT\\" ascii
		$cmd0 = "C:\\Windows\\System32\\cmd.exe" ascii fullword
		$lua0 = "client_recv" ascii fullword
		$lua1 = "client_send" ascii fullword
		$lua2 = "$LuaVersion: " ascii
		$sym0 = "VirtualAllocEx" wide fullword
		$sym1 = "kernel32.dll" wide fullword

	condition:
		all of them
}
