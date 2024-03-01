rule SIGNATURE_BASE_Deeppanda_Lot1
{
	meta:
		description = "Hack Deep Panda - lot1.tmp-pwdump"
		author = "Florian Roth (Nextron Systems)"
		id = "c72120a5-8637-580c-9856-e070dfb6df94"
		date = "2015-02-08"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_deeppanda.yar#L24-L49"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "5d201a0fb0f4a96cefc5f73effb61acff9c818e1"
		logic_hash = "92169a1288f30dc6008e1a8c9b2b700f878c90aa09634e36fea586e19657dbd1"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Unable to open target process: %d, pid %d" fullword ascii
		$s1 = "Couldn't delete target executable from remote machine: %d" fullword ascii
		$s2 = "Target: Failed to load SAM functions." fullword ascii
		$s5 = "Error writing the test file %s, skipping this share" fullword ascii
		$s6 = "Failed to create service (%s/%s), error %d" fullword ascii
		$s8 = "Service start failed: %d (%s/%s)" fullword ascii
		$s12 = "PwDump.exe" fullword ascii
		$s13 = "GetAvailableWriteableShare returned an error of %ld" fullword ascii
		$s14 = ":\\\\.\\pipe\\%s" fullword ascii
		$s15 = "Couldn't copy %s to destination %s. (Error %d)" fullword ascii
		$s16 = "dump logon session" fullword ascii
		$s17 = "Timed out waiting to get our pipe back" fullword ascii
		$s19 = "SetNamedPipeHandleState failed, error %d" fullword ascii
		$s20 = "%s\\%s.exe" fullword ascii

	condition:
		10 of them
}
