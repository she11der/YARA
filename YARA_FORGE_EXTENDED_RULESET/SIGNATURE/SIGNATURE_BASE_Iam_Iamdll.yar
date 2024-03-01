rule SIGNATURE_BASE_Iam_Iamdll : FILE
{
	meta:
		description = "Auto-generated rule - file iamdll.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "15e8ddac-af17-5509-b552-b4364af57c90"
		date = "2015-07-10"
		modified = "2023-12-05"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_passthehashtoolkit.yar#L76-L92"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "892de92f71941f7b9e550de00a57767beb7abe1171562e29428b84988cee6602"
		logic_hash = "ef7c66d2e1204a43921b6701812ea8a7bfa8e39e24d9396c95b725a4a4171010"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "LSASRV.DLL" fullword ascii
		$s1 = "iamdll.dll" fullword ascii
		$s2 = "ChangeCreds" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <115KB and all of them
}
