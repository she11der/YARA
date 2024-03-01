rule MALPEDIA_Win_Zeus_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "7fc58452-b8ed-5f5d-9c4b-1944a46dd13e"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zeus"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.zeus_auto.yar#L1-L231"
		license_url = "N/A"
		logic_hash = "9dc359b19db229cc8d91a3a8afe15f58c5fe776d823ff66891a661f0a8422765"
		score = 75
		quality = 73
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
		$sequence_0 = { eb58 833f00 7651 8b5f08 }
		$sequence_1 = { 8b3a 3b7d08 740a 40 }
		$sequence_2 = { 8d443604 50 a1???????? 57 }
		$sequence_3 = { 8d442440 50 8d442428 50 0fb64304 }
		$sequence_4 = { 8d442448 50 ff15???????? 0fb744244e }
		$sequence_5 = { 8d4c3110 81f90000a000 7715 8918 c7400400000200 89780c }
		$sequence_6 = { 8918 c7400400000200 89780c ff4208 890a c645ff01 }
		$sequence_7 = { 8d442460 50 e8???????? 8b4508 }
		$sequence_8 = { e8???????? 84c0 7442 6a10 }
		$sequence_9 = { 891d???????? 891d???????? ffd6 68???????? }
		$sequence_10 = { 8bf3 6810270000 ff35???????? ff15???????? }
		$sequence_11 = { 8d8db0fdffff e8???????? 8ad8 84db }
		$sequence_12 = { 8ac3 5b c20800 55 8bec 83e4f8 }
		$sequence_13 = { c9 c20400 55 8bec f6451802 }
		$sequence_14 = { 56 ff15???????? 5e 8ac3 5b c20800 }
		$sequence_15 = { 84c0 0f84ac000000 b809080002 3945f4 7713 807d0801 0f8598000000 }
		$sequence_16 = { 0f86e3000000 8b03 3509080002 3d5c5b4550 740b 3d59495351 }
		$sequence_17 = { c745f809080002 e8???????? 8ad8 f6450c04 7473 }
		$sequence_18 = { 807b0244 7429 83fe04 0f82ec000000 8b1b 81f309080002 81fb5d515047 }
		$sequence_19 = { ff35???????? e8???????? 5f 5e 8ac3 }
		$sequence_20 = { 8d470c 50 c707000e0000 c7470809080002 }
		$sequence_21 = { b8d5000000 e8???????? 68e6010000 68???????? 6809080002 8bc6 50 }
		$sequence_22 = { 81fb5d515047 7410 81fb4f4d4156 7408 81fb59495354 7506 b364 }
		$sequence_23 = { 81fb59495354 7506 b364 6a14 eb18 81fb5a5c4156 740c }

	condition:
		7 of them and filesize <319488
}