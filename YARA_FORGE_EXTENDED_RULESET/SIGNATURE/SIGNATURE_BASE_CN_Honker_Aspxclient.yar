rule SIGNATURE_BASE_CN_Honker_Aspxclient : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file AspxClient.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "7e38365c-ffe5-5fcd-8bd6-948d255d6e10"
		date = "2015-06-23"
		modified = "2022-12-21"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L505-L523"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "67569a89128f503a459eab3daa2032261507f2d2"
		logic_hash = "4d0a93434673952fed38e384db526275b9eb32bac9a207c91f792d4d113c40f1"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "\\tools\\hashq\\hashq.exe" wide
		$s2 = "\\Release\\CnCerT.CCdoor.Client.pdb" ascii
		$s3 = "\\myshell.mdb" wide
		$s4 = "injectfile" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and 3 of them
}
