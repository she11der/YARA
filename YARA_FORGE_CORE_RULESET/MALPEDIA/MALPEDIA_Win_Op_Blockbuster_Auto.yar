rule MALPEDIA_Win_Op_Blockbuster_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "25f80772-0fe0-5361-8b46-20a23fa9313b"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.op_blockbuster"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.op_blockbuster_auto.yar#L1-L321"
		license_url = "N/A"
		logic_hash = "7067748769cd92b2df2df661ece0caacb6285e4ff10828657376fad1bbae3d46"
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
		$sequence_0 = { 6a00 e8???????? 85c0 7407 83f802 }
		$sequence_1 = { f3ab 66ab aa 5f 85f6 }
		$sequence_2 = { ff15???????? 6808400000 6a40 ff15???????? }
		$sequence_3 = { 56 57 683c400000 6a40 }
		$sequence_4 = { e8???????? 6800400000 6a00 ff15???????? }
		$sequence_5 = { c701???????? 8b497c 85c9 7407 51 }
		$sequence_6 = { 8a08 80f920 7505 83c021 eb05 }
		$sequence_7 = { 68???????? 56 ff15???????? 68???????? 56 a3???????? e8???????? }
		$sequence_8 = { 56 50 8d45fc 6a04 50 }
		$sequence_9 = { 7412 68???????? 50 e8???????? 59 a3???????? 59 }
		$sequence_10 = { 3c70 7f04 0409 eb06 }
		$sequence_11 = { 3c69 7c08 3c70 7f04 }
		$sequence_12 = { 488b05???????? 4833c4 48898424d0030000 33c0 488be9 }
		$sequence_13 = { c3 56 53 6a01 57 e8???????? }
		$sequence_14 = { 56 6a00 ff15???????? 8bf8 85ff 7504 5f }
		$sequence_15 = { 8bc6 5f 5e c3 33c0 6a00 }
		$sequence_16 = { 33c0 ebac 498bcc ff15???????? 488d4d70 }
		$sequence_17 = { ff15???????? 85f6 7404 85c0 }
		$sequence_18 = { 57 e8???????? 56 e8???????? 83c414 b801000000 }
		$sequence_19 = { 68???????? 56 e8???????? 56 e8???????? 83c438 }
		$sequence_20 = { 0f84df010000 8b542444 488bcf 442bea 4585ed }
		$sequence_21 = { ff15???????? 85c0 0f84e7010000 488d558c 488d8dd0020000 ff15???????? }
		$sequence_22 = { c3 33c0 ebf8 53 33db 391d???????? 56 }
		$sequence_23 = { a3???????? 5e c3 68???????? ff15???????? 85c0 }
		$sequence_24 = { e8???????? 85c0 7429 488d542468 4c8bce 41b804000000 488bcf }
		$sequence_25 = { 83fb01 7524 488d942490010000 4d8bc4 488bcd }
		$sequence_26 = { 8b86d8974400 85c0 740e 50 e8???????? }
		$sequence_27 = { 83e03f 6bc830 8b0495d8974400 f644082801 7421 57 e8???????? }
		$sequence_28 = { c1fa06 8bc6 83e03f 6bc830 8b0495d8974400 885c0128 8b0495d8974400 }
		$sequence_29 = { 81ec54080000 56 57 33f6 b9ff010000 33c0 8dbdaef7ffff }
		$sequence_30 = { f3ab 8bca 83e103 f3aa 8b4df8 }
		$sequence_31 = { 57 50 ff5114 85c0 0f8c8c000000 }
		$sequence_32 = { ffd6 6a00 6a00 8d8424140c0000 6a00 }
		$sequence_33 = { 58 7577 ff7508 8b7d08 }

	condition:
		7 of them and filesize <74309632
}
