rule SIGNATURE_BASE_CN_Honker_Webshell__Serv_U_By_Goldsun_Asp3_Serv_U_Asp : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - from files Serv-U_by_Goldsun.asp, asp3.txt, Serv-U asp.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "e91e05e8-0f6d-57a7-a649-a834733f17c8"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L880-L899"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "b733e80f234a85a4f65eedd94f535860b4da464adb80a91afc547a8d96b5dc7a"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "d4d7a632af65a961a1dbd0cff80d5a5c2b397e8c"
		hash1 = "87c5a76989bf08da5562e0b75c196dcb3087a27b"
		hash2 = "cee91cd462a459d31a95ac08fe80c70d2f9c1611"

	strings:
		$s1 = "c.send loginuser & loginpass & mt & deldomain & quit" fullword ascii
		$s2 = "loginpass = \"Pass \" & pass & vbCrLf" fullword ascii
		$s3 = "b.send \"User go\" & vbCrLf & \"pass od\" & vbCrLf & \"site exec \" & cmd & vbCr" ascii

	condition:
		filesize <444KB and all of them
}
