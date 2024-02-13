rule MALPEDIA_Win_Troldesh_Auto___FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "7a3f582f-20a8-506d-8165-0b2ca7b385f0"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.troldesh"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.troldesh_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "0484cce0fd00b2a95d24b675e3e6f5f144cbe86411aeac4268060b95d7df46bc"
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
		$sequence_0 = { ff74241c 8d44247c ff74241c 50 e8???????? 8b8e18050000 83c40c }
		$sequence_1 = { e8???????? 8b4510 8b4008 68ffffff7f 6a00 6a0a ff30 }
		$sequence_2 = { eb17 51 50 8d45d8 50 e8???????? 8b4514 }
		$sequence_3 = { ff7314 e8???????? 59 8b4df4 89431c 85c0 7511 }
		$sequence_4 = { e9???????? 8b4ddc e8???????? 33c0 83c604 8975f8 8b7508 }
		$sequence_5 = { e8???????? a3???????? e8???????? 8bf0 8974242c e8???????? 6a00 }
		$sequence_6 = { ff7720 89742414 56 e8???????? 59 59 85c0 }
		$sequence_7 = { ff7508 8bcf 56 ffb754010000 6a04 e8???????? 83c410 }
		$sequence_8 = { e8???????? 85c0 7419 6a14 8d500c 8d4de0 e8???????? }
		$sequence_9 = { e8???????? 8b4514 660fbe00 0fb7c0 50 6a01 e8???????? }

	condition:
		7 of them and filesize <3915776
}