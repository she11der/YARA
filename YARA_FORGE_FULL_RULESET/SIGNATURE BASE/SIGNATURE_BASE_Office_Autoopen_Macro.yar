rule SIGNATURE_BASE_Office_Autoopen_Macro : FILE
{
	meta:
		description = "Detects an Microsoft Office file that contains the AutoOpen Macro function"
		author = "Florian Roth (Nextron Systems)"
		id = "9774d96c-4d15-5a54-8fe2-e06372d9c4ec"
		date = "2015-05-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/general_officemacros.yar#L2-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "23c834828e7a9ea966e5d7247881bbbf9180b8f08297e36cd36d2ba5f621c70d"
		score = 40
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4d00695d5011427efc33c9722c61ced2"
		hash2 = "63f6b20cb39630b13c14823874bd3743"
		hash3 = "66e67c2d84af85a569a04042141164e6"
		hash4 = "a3035716fe9173703941876c2bde9d98"
		hash5 = "7c06cab49b9332962625b16f15708345"
		hash6 = "bfc30332b7b91572bfe712b656ea8a0c"
		hash7 = "25285b8fe2c41bd54079c92c1b761381"

	strings:
		$s1 = "AutoOpen" ascii fullword
		$s2 = "Macros" wide fullword

	condition:
		( uint32be(0)==0xd0cf11e0 or uint32be(0)==0x504b0304) and all of ($s*) and filesize <300000
}
