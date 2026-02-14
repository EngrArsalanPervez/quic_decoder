project('quic_secrets', 'c',
  version : '0.1',
  default_options : ['warning_level=2']
)

# 1. Define Dependencies
dependencies = [
  dependency('glib-2.0'),
  dependency('libgcrypt'),
  dependency('pcap'),
]

# 2. Define Source Files
# It's cleaner to put them in a list
sources = [
  'main.c',
  'quic_d.c'
]

# 3. Build the Executable
# Meson will compile both .c files and link them together
executable('quic_secrets',
  sources,
  dependencies : dependencies,
  install : true
)
