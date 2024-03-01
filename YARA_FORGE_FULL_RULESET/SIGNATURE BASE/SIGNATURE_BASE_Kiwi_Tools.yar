rule SIGNATURE_BASE_Kiwi_Tools : FILE
{
	meta:
		description = "Chinese Hacktool Set"
		author = "Florian Roth (Nextron Systems)"
		id = "000f0081-b035-5c73-8da2-addde2b55303"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L2521-L2554"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ce7b3c7d57740257013d9d589444a3b53e81254619bd3f09ece917c70bba03ce"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "e57e79f190f8a24ca911e6c7e008743480c08553"
		hash1 = "55d5dabd96c44d16e41f70f0357cba1dda26c24f"
		hash2 = "7ac7541e20af7755b7d8141c5c1b7432465cabd8"
		hash3 = "9fbfe3eb49d67347ab57ae743f7542864bc06de6"
		hash4 = "5c90d648c414bdafb549291f95fe6f27c0c9b5ec"
		hash5 = "7addce4434670927c4efaa560524680ba2871d17"
		hash6 = "28c5c0bdb7786dc2771672a2c275be7d9b742ec7"
		hash7 = "b5c93489a1b62181594d0fb08cc510d947353bc8"
		hash8 = "6acecd18fc7da1c5eb0d04e848aae9ce59d2b1b5"
		hash9 = "5d578df9a71670aa832d1cd63379e6162564fb6b"
		hash10 = "febadc01a64a071816eac61a85418711debaf233"
		hash11 = "569ca4ff1a5ea537aefac4a04a2c588c566c6d86"
		hash12 = "56a61c808b311e2225849d195bbeb69733efe49a"
		hash13 = "8bd6c9f2e8be3e74bd83c6a2d929f8a69422fb16"
		hash14 = "44825e848bc3abdb6f31d0a49725bb6f498e9ccc"
		hash15 = "f661d6516d081c37ab7da0f4ec21b2cc6a9257c6"
		hash16 = "20facf1fa2d87cccf177403ca1a7852128a9a0ab"
		hash17 = "6e0ffa472d63fdda5abc4c1b164ba8724dcb25b5"

	strings:
		$s1 = "http://blog.gentilkiwi.com/mimikatz" ascii
		$s2 = "Benjamin Delpy" fullword ascii
		$s3 = "GlobalSign" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and all of them
}
