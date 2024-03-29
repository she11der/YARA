rule SIGNATURE_BASE_Remotecmd : FILE
{
	meta:
		description = "Detects a remote access tool used by APT groups - file RemoteCmd.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "384f37f3-4562-5d79-9793-0384c43d4602"
		date = "2016-09-08"
		modified = "2022-12-21"
		reference = "http://goo.gl/igxLyF"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_buckeye.yar#L30-L49"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "873cc02674e386577e86cb9b702265c25dd24b1f203741e8628e30c191dc99e0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "5264d1de687432f8346617ac88ffcb31e025e43fc3da1dad55882b17b44f1f8b"

	strings:
		$s1 = "RemoteCmd.exe" fullword wide
		$s2 = "\\Release\\RemoteCmd.pdb" ascii
		$s3 = "RemoteCmd [ComputerName] [Executable] [Param1] [Param2] ..." fullword wide
		$s4 = "http://{0}:65101/CommandEngine" fullword wide
		$s5 = "Brenner.RemoteCmd.Client" fullword ascii
		$s6 = "$b1888995-1ee5-4f6d-82df-d2ab8ae73d63" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <50KB and 2 of them ) or (4 of them )
}
