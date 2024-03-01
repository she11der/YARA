rule MALPEDIA_Win_Glitch_Pos_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "f95f1f9c-9245-5181-9c68-89e1dc86d5ed"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.glitch_pos"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.glitch_pos_auto.yar#L1-L128"
		license_url = "N/A"
		logic_hash = "27fcd67a00a15c3597cc82166656216e7d9a07529c9493cfeef64f5dddb0c04c"
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
		$sequence_0 = { 83a5d8feffff00 8b45b8 898518ffffff 8d45d0 50 8b8518ffffff }
		$sequence_1 = { 8b4508 8b00 ff7508 ff9028070000 668b45d4 662d0100 }
		$sequence_2 = { ffb504ffffff e8???????? 89855cfeffff eb07 83a55cfeffff00 8d8d5cffffff e8???????? }
		$sequence_3 = { e8???????? 8d8520ffffff 50 8d8530ffffff 50 8d45dc 50 }
		$sequence_4 = { 68???????? 68???????? e8???????? c78568feffff2cc34600 eb0a c78568feffff2cc34600 8b8568feffff }
		$sequence_5 = { eb07 83a5fcfdffff00 8d45c4 50 8d45cc 50 6a02 }
		$sequence_6 = { 8b4d10 660301 0f8058040000 668945ec 8b4508 8b00 }
		$sequence_7 = { 83c40c 68???????? 6a00 6a06 8b4508 }
		$sequence_8 = { 8d45b4 50 8d45b8 50 6a03 e8???????? }
		$sequence_9 = { 8bec 83ec0c 68???????? 64a100000000 50 64892500000000 b8bc000000 }

	condition:
		7 of them and filesize <1024000
}
