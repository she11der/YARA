rule MALPEDIA_Win_Unidentified_041_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "54c40e17-80e5-57a5-babe-281dfc0f14df"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_041"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.unidentified_041_auto.yar#L1-L133"
		license_url = "N/A"
		logic_hash = "72336cc9bc2b4e7b40dbb912cf40721cd5c8d54310aa5ce8f7ef42d8a402b398"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { ff761c ff7618 ff7304 e8???????? 8d45bf c645bf0d 50 }
		$sequence_1 = { 885d9b e9???????? 391f 75c7 385e04 752e }
		$sequence_2 = { 8b3f 8d44242c 50 53 68???????? 57 6a02 }
		$sequence_3 = { c645fc02 8b08 52 53 50 ff5118 85c0 }
		$sequence_4 = { eb05 be57000780 5f 8bc6 5e 5b c20400 }
		$sequence_5 = { 85c0 7509 56 e8???????? 59 eba7 8d47ff }
		$sequence_6 = { ff75e0 e8???????? 8b45f0 83c418 2b06 8bce c1f802 }
		$sequence_7 = { 7430 ff7508 8bfe 33c0 ab ab ab }
		$sequence_8 = { ff5024 85c0 0f8889040000 33c0 8dbd22fdffff 66898520fdffff ab }
		$sequence_9 = { 8d8d54ffffff e8???????? 8bc6 e9???????? ff15???????? 50 8d8d28ffffff }

	condition:
		7 of them and filesize <1097728
}
