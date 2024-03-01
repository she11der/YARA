rule MALPEDIA_Win_Multigrain_Pos_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "a0867608-6152-525b-bb1e-ffd07d70fa86"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.multigrain_pos"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.multigrain_pos_auto.yar#L1-L120"
		license_url = "N/A"
		logic_hash = "e5b2ff30a169eba30bec1ec0cb7a796ca39923255067b4e9a8563c5dcf8b4ca3"
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
		$sequence_0 = { c745fc00000000 8b7518 b8cdcccccc 8d0cf504000000 }
		$sequence_1 = { 57 e8???????? 83c404 6a00 c746140f000000 }
		$sequence_2 = { c645fc01 e8???????? 83c408 83bdb4fdffff08 720e ffb5a0fdffff }
		$sequence_3 = { 0f8530020000 68c8000000 50 8d85c4feffff 50 e8???????? 83c40c }
		$sequence_4 = { 0fb64c1e01 c1e905 894df4 eb07 c745f400000000 0fb60c1e 8b55f8 }
		$sequence_5 = { 8bd0 8d4dd8 c645fc03 e8???????? }
		$sequence_6 = { c745e0ffffffff c745e800000000 c745e400000000 c745ec01000000 c745f401000000 }
		$sequence_7 = { e8???????? 83c404 56 ffd3 33db 395f10 56 }
		$sequence_8 = { 81eca8040000 a1???????? 33c4 898424a4040000 56 57 }
		$sequence_9 = { c745f400000000 8b4df0 8b5df8 0fb609 83e101 }

	condition:
		7 of them and filesize <286720
}
