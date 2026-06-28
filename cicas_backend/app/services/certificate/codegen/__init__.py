"""Zlint code generation pipeline — unified canonical implementation.

File layout
------------
  det_codegen      deterministic IR→DSL synthesis (zero-LLM; calls app.rule_ir_to_dsl)
  tree_prompt      LLM prompt templates for tree synthesis
  tree_codegen     LLM tree synthesis (fallback when det fails)
  runner            render DSL tree → Go source → go build
  synonym_judge     LLM synonymy judge + judge_vote (codegen emission gate)
                    judge_expresses / judge_vote  ← binary Expresses/Does_Not_Express
                    judge_synonymy                ← synonymy (extraction side, legacy)
                    call_llm / parse_json_block   ← unified LLM call (ai.ailink1.com)
  oracle_pipeline   tree_all_certified / CERTIFIED atom set
  atom_oracle       CERTIFIED whitelist + lint harness (load / lint / sentinel)
  dsl               tv-side DSL atoms and parse/render (go-codegen target)
  vocab             zlint vocabulary + OID name map

Architecture
------------
  codegen route (canonical) = rule_ir_to_dsl → det_codegen.deterministic_tree
  experiments call backend   = codegen/generate() REST endpoint or direct import
  experiments MUST NOT implement its own codegen logic
"""
