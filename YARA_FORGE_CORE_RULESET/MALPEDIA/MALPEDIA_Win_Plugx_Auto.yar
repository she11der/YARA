rule MALPEDIA_Win_Plugx_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "f3050f8b-cffb-5dba-854a-dbf0ccdc7dc1"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.plugx"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.plugx_auto.yar#L1-L275"
		license_url = "N/A"
		logic_hash = "dee163361f083ebb03bd1347d736d4fc9d87c0c2c6fd15ac5989d8dd6f5a5f80"
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
		$sequence_0 = { 51 56 57 6a1c 8bf8 }
		$sequence_1 = { 33d2 f7f3 33d2 8945fc }
		$sequence_2 = { 55 8bec a1???????? 83ec5c 53 }
		$sequence_3 = { 55 8bec 51 0fb74612 }
		$sequence_4 = { 51 53 6a00 6a00 6a02 ffd0 85c0 }
		$sequence_5 = { 41 3bca 7ce0 3bca }
		$sequence_6 = { 56 8b750c 8b4604 050070ffff }
		$sequence_7 = { 6a00 6800100000 6800100000 68ff000000 6a00 6803000040 }
		$sequence_8 = { e8???????? 3de5030000 7407 e8???????? }
		$sequence_9 = { e8???????? 85c0 7508 e8???????? 8945fc }
		$sequence_10 = { 50 ff15???????? a3???????? 8b4d18 }
		$sequence_11 = { 85c0 7413 e8???????? 3de5030000 }
		$sequence_12 = { e8???????? 85c0 7407 b84f050000 }
		$sequence_13 = { e8???????? 85c0 750a e8???????? 8945fc }
		$sequence_14 = { 6a00 6a04 6a00 6a01 6800000040 57 }
		$sequence_15 = { 6a00 6819000200 6a00 6a00 6a00 51 }
		$sequence_16 = { 56 56 6a01 56 ffd0 }
		$sequence_17 = { 85c0 750d e8???????? 8945f4 }
		$sequence_18 = { 57 e8???????? eb0c e8???????? }
		$sequence_19 = { 50 ff75e8 6802000080 e8???????? }
		$sequence_20 = { 6a00 ff7028 e8???????? 83c408 85c0 }
		$sequence_21 = { 6808020000 6a00 ff742450 e8???????? 83c40c }
		$sequence_22 = { 6a02 6a00 e8???????? c705????????00000000 }
		$sequence_23 = { 6800080000 68???????? e8???????? 6800080000 68???????? e8???????? }
		$sequence_24 = { 5e 5f 5b 5d c3 64a118000000 }
		$sequence_25 = { 81ec90010000 e8???????? e8???????? e8???????? }
		$sequence_26 = { 68???????? 6830750000 68e8030000 ff36 }
		$sequence_27 = { 5f 5b 5d c20400 55 53 57 }
		$sequence_28 = { 50 56 ffb42480000000 ff15???????? }
		$sequence_29 = { 6808020000 6a00 ff74242c e8???????? }
		$sequence_30 = { 6a01 6a00 e8???????? a3???????? 6800080000 }

	condition:
		7 of them and filesize <1284096
}