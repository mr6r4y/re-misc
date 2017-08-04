# Variable init
# -------------

e scr.color = true
e scr.utf8 = true
e dbg.bep = loader

e asm.syntax = intel
e asm.varsub_only = false

e cfg.fortunes = false

e stack.anotated = true
e stack.bytes = true


# Bug: graph.gv.graph is not included in .dot files
e graph.gv.graph = bgcolor=white,splines=ortho

e graph.font = Monospace
e graph.gv.node = shape=box,color=black

e graph.offset = true
e graph.cmtright = true


# Show relative offset
# e asm.reloff = true

# Cache needed for ESIL
# NOTE: It seems that when "io.cache" is true the breaks in "ood" are missed when "dc"
# e io.cache = true

# -------------


# Macro defs
# ----------

# pd and pdf with relative offset
"(pdroff x y, e asm.reloff=true; pd $0 @ $1; e asm.reloff=false)"
"(pdfroff x, e asm.reloff=true; pdf @ $0; e asm.reloff=false)"

# ----------
