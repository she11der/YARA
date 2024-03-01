rule SIGNATURE_BASE_Webshell_Sincap_1_0
{
	meta:
		description = "PHP Webshells Github Archive - file Sincap 1.0.php"
		author = "Florian Roth (Nextron Systems)"
		id = "38d39739-660f-596d-a297-1f0dfe530797"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L5691-L5706"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "9b72635ff1410fa40c4e15513ae3a496d54f971c"
		logic_hash = "0cb8851285bd55b0b613ec4c46ab88142e2cbba7e527ad510b008cfb342af221"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s4 = "</font></span><a href=\"mailto:shopen@aventgrup.net\">" fullword
		$s5 = "<title>:: AventGrup ::.. - Sincap 1.0 | Session(Oturum) B" fullword
		$s9 = "</span>Avrasya Veri ve NetWork Teknolojileri Geli" fullword
		$s12 = "while (($ekinci=readdir ($sedat))){" fullword
		$s19 = "$deger2= \"$ich[$tampon4]\";" fullword

	condition:
		2 of them
}
