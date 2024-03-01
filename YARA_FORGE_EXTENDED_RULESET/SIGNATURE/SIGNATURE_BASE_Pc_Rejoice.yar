rule SIGNATURE_BASE_Pc_Rejoice : FILE
{
	meta:
		description = "Chinese Hacktool Set - file rejoice.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "197b5a21-e1ed-5ea8-b7f2-e84684aedc54"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L2049-L2067"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "fe634a9f5d48d5c64c8f8bfd59ac7d8965d8f372"
		logic_hash = "9e22a98b5065a95a7f169fda8d6d4112101bffa11a1407e03ec152db41857206"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "@members.3322.net/dyndns/update?system=dyndns&hostname=" fullword ascii
		$s2 = "http://www.xxx.com/xxx.exe" fullword ascii
		$s3 = "@ddns.oray.com/ph/update?hostname=" fullword ascii
		$s4 = "No data to read.$Can not bind in port range (%d - %d)" fullword wide
		$s5 = "ListViewProcessListColumnClick!" fullword ascii
		$s6 = "http://iframe.ip138.com/ic.asp" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and 3 of them
}
