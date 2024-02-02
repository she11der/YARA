rule MALPEDIA_Win_Loup_Auto___FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "f9d1b576-d285-5231-afcb-2e4f16800d77"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.loup"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.loup_auto.yar#L1-L121"
		license_url = "N/A"
		logic_hash = "ff0573e37f479d8813fb50aaed8f812906a0bad4de56fabb213fa961c6890498"
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
		$sequence_0 = { 83c404 85c0 741c 0fb745f4 50 e8???????? }
		$sequence_1 = { 81781422059319 740c 8b4dfc 81791400409901 7522 e8???????? 8b55fc }
		$sequence_2 = { 8b0d???????? 898dc8fbffff 8b15???????? 8995ccfbffff a1???????? 8985d0fbffff }
		$sequence_3 = { 8b85d0f1ffff 53 56 ff3485647b4100 50 }
		$sequence_4 = { 8b7508 57 85d2 744f 33ff 393a }
		$sequence_5 = { 81f247656e75 b804000000 6bc803 8b440de0 35696e6549 }
		$sequence_6 = { 8b4df4 84c0 0f84defeffff c745dc01000000 e9???????? 5f 5e }
		$sequence_7 = { 668945e8 33c0 668945ea c745ee01000000 b804000000 668945ec }
		$sequence_8 = { b804000000 c1e002 c784055cffffff01000000 8d855cffffff 8945d5 }
		$sequence_9 = { 85c0 7443 0fb745f4 50 }

	condition:
		7 of them and filesize <257024
}