rule MALPEDIA_Win_Retefe_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "f3caa6e6-3618-52a1-825b-c9f70c1ac6ab"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.retefe"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.retefe_auto.yar#L1-L263"
		license_url = "N/A"
		logic_hash = "60c0df86aaa8e365109479b1ca3f3fca53ccf95fd2fbd33ae20876e0704e51b2"
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
		$sequence_0 = { 6a00 6a01 ff15???????? 8bf0 85f6 7410 6a09 }
		$sequence_1 = { 51 8bf8 ffd6 85c0 }
		$sequence_2 = { 68f5000000 50 ff15???????? b801000000 }
		$sequence_3 = { e8???????? 6a08 e8???????? 894604 }
		$sequence_4 = { 6a24 6a5a 6a24 e8???????? 81c494000000 }
		$sequence_5 = { 8b4e04 8901 8b4e04 33c0 83c404 394104 }
		$sequence_6 = { 6a0e 6aeb 6a1a 6a96 6a0d }
		$sequence_7 = { 894604 83c404 8bc6 e8???????? }
		$sequence_8 = { 51 ff15???????? 8b95d8efffff 50 52 ff15???????? 50 }
		$sequence_9 = { 52 e8???????? 8b4e04 8901 }
		$sequence_10 = { 6ad1 6a1a 6a55 6ad7 6ad1 }
		$sequence_11 = { 880c10 8b4e04 40 3b4104 }
		$sequence_12 = { 50 e8???????? 83c408 e8???????? 99 b960f59000 }
		$sequence_13 = { 8bec 837d0c00 7409 b80b000280 }
		$sequence_14 = { 56 33f6 8b86a0bf4200 85c0 740e }
		$sequence_15 = { 43 85ff 0f851fffffff 5f }
		$sequence_16 = { 6a00 ffb42424200000 e8???????? 8b8c2418200000 }
		$sequence_17 = { 8b0495a0bf4200 f644082801 7421 57 e8???????? }
		$sequence_18 = { 46 85f6 7410 83fe01 75a0 }
		$sequence_19 = { 0fb611 0fb6c0 eb17 81fa00010000 7313 8a87ccb14200 }
		$sequence_20 = { 8b742414 85f6 7553 32c0 }
		$sequence_21 = { 57 81fb00020000 0f8daa000000 6800080000 }
		$sequence_22 = { 8b4218 a3???????? 8b4a08 890d???????? 8b420c }
		$sequence_23 = { 33c0 668906 8b7c2414 8d5f20 }
		$sequence_24 = { e8???????? 8b404c 83b8a800000000 7512 8b04bda0bf4200 807c302900 7504 }
		$sequence_25 = { 88048d93404300 88048d923c4300 84d2 7412 }
		$sequence_26 = { 8b7004 8b38 4e 8bce e8???????? }
		$sequence_27 = { 8b4d08 85c9 7512 e8???????? 5e }
		$sequence_28 = { 5f 894df0 8b34cd58224100 8b4d08 6a5a 2bce }

	condition:
		7 of them and filesize <843776
}
