rule ESET_Mumblehard_Packer
{
	meta:
		description = "Mumblehard i386 assembly code responsible for decrypting Perl code"
		author = "Marc-Etienne M.Léveillé"
		id = "981c18e3-ac28-54f5-97ab-44b1d12a1389"
		date = "2015-04-07"
		modified = "2015-05-01"
		reference = "http://www.welivesecurity.com"
		source_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/mumblehard/mumblehard_packer.yar#L32-L47"
		license_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/LICENSE"
		logic_hash = "a04f50a7054c4ce8ad9be4e7f3373ad4f36eb9443e223601974e852c25603f5f"
		score = 75
		quality = 80
		tags = ""
		version = "1"

	strings:
		$decrypt = { 31 db  [1-10]  ba ?? 00 00 00  [0-6]  (56 5f |  89 F7)
                     39 d3 75 13 81 fa ?? 00 00 00 75 02 31 d2 81 c2 ?? 00 00
                     00 31 db 43 ac 30 d8 aa 43 e2 e2 }

	condition:
		$decrypt
}
