meta:
  id: t2dag
  title: "Tundra2 DAG Format"
  file-extension: dag
  endian: le

# Structure naming pattern:
#  - _ptr                =  sequence offset
#  - _deref               = given bash, offset
#  - _array               = sequence offset, length
#  - _array_fixed         = given length
#  - _array_deref         = given base, offset, length
#  - _index               = index into known array

seq:
  - id: magic
    contents: [0x13, 0x23, 0x99, 0x6d ]
  - id: node_count
    type: u4
  - id: node_guids
    type: fast_hash_array_fixed(node_count)
  - id: nodes
    type: node_array_fixed(node_count)
  - id: passes
    type: string_array
  - id: config_count
    type: u4
  - id: config_names
    type: string_array_fixed(config_count)
  - id: config_name_hashes
    type: hash32_array_fixed(config_count)
  - id: variant_count
    type: u4
  - id: variant_names
    type: string_array_fixed(variant_count)
  - id: variant_name_hashes
    type: hash32_array_fixed(variant_count)
  - id: subvariant_count
    type: u4
  - id: subvariant_names
    type: string_array_fixed(subvariant_count)
  - id: subvariant_name_hashes
    type: hash32_array_fixed(subvariant_count)
  - id: build_tuples
    type: build_tuple_array
  - id: default_config
    type: config_index
  - id: default_variant
    type: variant_index
  - id: default_subvariant
    type: subvariant_index
  - id: file_signatures
    type: file_signature_array
  - id: glob_signatures
    type: placeholder_array
  - id: sha_extension_hashes
    type: djb2_hash_array
  - id: max_expensive_count
    type: s4
  - id: state_filename
    type: filename
  - id: state_filename_tmp
    type: filename
  - id: scan_cache_filename
    type: filename
  - id: scan_cache_filename_tmp
    type: filename
  - id: digest_cache_filename
    type: filename
  - id: digest_cache_filename_tmp
    type: filename

types:

  node:
    seq:
      - id: action
        type: string
      - id: preaction
        type: string
      - id: annotation
        type: string
      - id: pass_index
        type: u4
      - id: dependencies
        type: node_index_array
      - id: backlinks
        type: node_index_array
      - id: input_files
        type: filename_and_hash_array
      - id: output_files
        type: filename_and_hash_array
      - id: aux_output_files
        type: filename_and_hash_array
      - id: env_vars
        type: env_var_array
      - id: scanner
        type: scanner_ptr
      - id: flags
        type: u4
      - id: is_overwrite
        type: flag32_test( flags, 1 )
      - id: is_precious_outputs
        type: flag32_test( flags, 2 )
      - id: is_expensive
        type: flag32_test( flags, 4 )

  node_by_index:
    params:
      - id: node_index
        type: u4
    instances:
      deref:
        value: _root.nodes.array.elements[node_index]
        if: node_index < _root.node_count
      is_valid:
        value: node_index < _root.node_count

  config_name_by_index:
    params:
      - id: config_index
        type: u4
    instances:
      deref:
        value: _root.config_names.array.elements[config_index].ptr.deref
        if: config_index < _root.config_count
      is_valid:
        value: config_index < _root.config_count

  config_name_hash_by_index:
    params:
      - id: config_index
        type: u4
    instances:
      deref:
        value: _root.config_name_hashes.array.elements[config_index]
        if: config_index < _root.config_count
      is_valid:
        value: config_index < _root.config_count

  variant_name_by_index:
    params:
      - id: variant_index
        type: u4
    instances:
      deref:
        value: _root.variant_names.array.elements[variant_index].ptr.deref
        if: variant_index < _root.variant_count
      is_valid:
        value: variant_index < _root.variant_count

  variant_name_hash_by_index:
    params:
      - id: variant_index
        type: u4
    instances:
      deref:
        value: _root.variant_name_hashes.array.elements[variant_index]
        if: variant_index < _root.variant_count
      is_valid:
        value: variant_index < _root.variant_count

  subvariant_name_by_index:
    params:
      - id: subvariant_index
        type: u4
    instances:
      deref:
        value: _root.subvariant_names.array.elements[subvariant_index].ptr.deref
        if: subvariant_index < _root.subvariant_count
      is_valid:
        value: subvariant_index < _root.subvariant_count

  subvariant_name_hash_by_index:
    params:
      - id: subvariant_index
        type: u4
    instances:
      deref:
        value: _root.subvariant_name_hashes.array.elements[subvariant_index]
        if: subvariant_index < _root.subvariant_count
      is_valid:
        value: subvariant_index < _root.subvariant_count

  node_array_fixed:
    params:
      - id: element_count 
        type: u4
    seq:
      - id: offset
        type: u4
      - id: array 
        type: node_array_deref( _io.pos-4, offset, element_count )
        if: element_count != 0
    instances:
      is_empty:
        value: element_count == 0

  node_array_deref:
    params:
      - id: base 
        type: u4
      - id: offset
        type: u4
      - id: element_count
        type: u4
    instances:
      elements:
        pos: base+offset
        type: node
        repeat: expr
        repeat-expr: element_count
      
  flag32_test:
    params:
      - id: flags
        type: u4
      - id: test
        type: u4
    instances:
      result:
        value: (flags & test) != 0

  scanner:
    seq:
      - id: scanner_type
        type: u4
      - id: include_paths
        type: string_array
      - id: scanner_guid
        type: fast_hash

  scanner_ptr:
    seq:
      - id: offset
        type: u4
      - id: ptr
        type: scanner_deref( _io.pos-4, offset )
        if: offset != 0
    instances:
      is_null:
        value: offset == 0

  scanner_deref:
    params:
      - id: base
        type: u4
      - id: offset
        type: u4
    instances:
      deref:
        pos: base+offset
        type: scanner

  env_var:
    seq:
      - id: name
        type: string
      - id: value
        type: string

  env_var_array:
    seq:
      - id: element_count
        type: u4
      - id: offset
        type: u4
      - id: array 
        type: env_var_array_deref( _io.pos-4, offset, element_count )
        if: element_count != 0
    instances:
      is_empty:
        value: element_count == 0

  env_var_array_deref:
    params:
      - id: base 
        type: u4
      - id: offset
        type: u4
      - id: element_count
        type: u4
    instances:
      elements:
        pos: base+offset
        type: env_var
        repeat: expr
        repeat-expr: element_count

  filename_and_hash:
    seq:
      - id: filename 
        type: filename
      - id: filename_hash
        type: hash32

  filename_and_hash_array:
    seq:
      - id: element_count
        type: u4
      - id: offset
        type: u4
      - id: array
        type: filename_and_hash_array_deref( _io.pos-4, offset, element_count )
        if: element_count != 0
    instances:
      is_empty:
        value: element_count == 0

  filename_and_hash_array_deref:
    params:
      - id: base 
        type: u4
      - id: offset
        type: u4
      - id: element_count
        type: u4
    instances:
      elements:
        pos: base+offset
        type: filename_and_hash
        repeat: expr
        repeat-expr: element_count

  filename:
    seq:
      - id: path
        type: string

  hash32:
    seq:
      - id: as_uint32
        type: u4

  node_index:
    seq:
      - id: node_index
        type: u4
      - id: get_node
        type: node_by_index(node_index)

  node_index_array:
    seq:
      - id: element_count
        type: u4
      - id: offset
        type: u4
      - id: array
        type: node_index_array_deref( _io.pos-4, offset, element_count )
        if: element_count != 0
    instances:
      is_empty:
        value: element_count == 0

  node_index_array_deref:
    params:
      - id: base 
        type: u4
      - id: offset
        type: u4
      - id: element_count
        type: u4
    instances:
      elements:
        pos: base+offset
        type: node_index
        repeat: expr
        repeat-expr: element_count

  fast_hash_array_fixed:
    params:
      - id: element_count
        type: u4
    seq:
      - id: offset
        type: u4
      - id: array
        type: fast_hash_array_deref( _io.pos-4, offset, element_count )
        if: element_count != 0
    instances:
      is_empty:
        value: element_count == 0

  fast_hash_array_deref:
    params:
      - id: base 
        type: u4
      - id: offset
        type: u4
      - id: element_count
        type: u4
    instances:
      elements:
        pos: base+offset
        type: fast_hash
        repeat: expr
        repeat-expr: element_count

  fast_hash:
    seq:
      - id: as_str
        type: u1
        repeat: expr
        repeat-expr: 16

  djb2_hash_array:
    seq:
      - id: element_count
        type: u4
      - id: offset
        type: u4
      - id: array
        type: djb2_hash_array_deref( _io.pos-4, offset, element_count )
        if: element_count != 0
    instances:
      is_empty:
        value: element_count == 0

  djb2_hash_array_deref:
    params:
      - id: base 
        type: u4
      - id: offset
        type: u4
      - id: element_count
        type: u4
    instances:
      elements:
        pos: base+offset
        type: djb2_hash
        repeat: expr
        repeat-expr: element_count

  djb2_hash:
    seq:
      - id: as_str
        type: u1
        repeat: expr
        repeat-expr: 16

  string:
    seq:
      - id: offset
        type: u4
      - id: ptr
        type: string_deref( _io.pos-4, offset )
        if: offset != 0
    instances:
      is_null:
        value: offset == 0

  string_deref:
    params:
      - id: base
        type: u4
      - id: offset
        type: u4
    instances:
      deref:
        pos: base+offset
        type: cstr_utf8

  cstr_utf8:
    seq:
      - id: as_utf8
        type: strz
        encoding: UTF-8

  string_array:
    seq:
      - id: element_count
        type: u4
      - id: offset
        type: u4
      - id: array
        type: string_array_deref( _io.pos-4, offset, element_count )
        if: element_count != 0
    instances:
      is_empty:
        value: element_count == 0

  string_array_fixed:
    params:
      - id: element_count
        type: u4
    seq:
      - id: offset
        type: u4
      - id: array
        type: string_array_deref( _io.pos-4, offset, element_count )
        if: element_count != 0
    instances:
      is_empty:
        value: element_count == 0

  string_array_deref:
    params:
      - id: base
        type: u4
      - id: offset
        type: u4
      - id: element_count
        type: u4
    instances:
      elements:
        pos: base+offset
        type: string
        repeat: expr
        repeat-expr: element_count

  config_index:
    seq:
      - id: config_index
        type: u4
      - id: get_config_name
        type: config_name_by_index(config_index)
      - id: get_config_name_hash
        type: config_name_hash_by_index(config_index)

  variant_index:
    seq:
      - id: variant_index
        type: u4
      - id: get_variant_name
        type: variant_name_by_index(variant_index)
      - id: get_variant_name_hash
        type: variant_name_hash_by_index(variant_index)

  subvariant_index:
    seq:
      - id: subvariant_index
        type: u4
      - id: get_subvariant_name
        type: subvariant_name_by_index(subvariant_index)
      - id: get_subvariant_name_hash
        type: subvariant_name_hash_by_index(subvariant_index)

  hash32_array_fixed:
    params:
      - id: element_count
        type: u4
    seq:
      - id: offset
        type: u4
      - id: array
        type: hash32_array_deref( _io.pos-4, offset, element_count )
        if: element_count != 0
    instances:
      is_empty:
        value: element_count == 0

  hash32_array_deref:
    params:
      - id: base
        type: u4
      - id: offset
        type: u4
      - id: element_count
        type: u4
    instances:
      elements:
        pos: base+offset
        type: hash32
        repeat: expr
        repeat-expr: element_count

  build_tuple_array:
    seq:
      - id: element_count 
        type: u4
      - id: offset
        type: u4
      - id: array
        type: build_tuple_array_deref( _io.pos-4, offset, element_count )
        if: element_count != 0
    instances:
      is_empty:
        value: element_count == 0

  build_tuple_array_deref:
    params:
      - id: base
        type: u4
      - id: offset
        type: u4
      - id: element_count 
        type: u4
    instances:
      elements:
        pos: base+offset
        type: build_tuple
        repeat: expr
        repeat-expr: element_count 

  build_tuple:
    seq:
      - id: config
        type: config_index
      - id: variant
        type: variant_index
      - id: subvariant
        type: subvariant_index
      - id: default_nodes
        type: node_index_array
      - id: always_nodes
        type: node_index_array
      - id: named_nodes
        type: named_node_array

  placeholder_array:
    seq:
      - id: element_count
        type: u4
      - id: offset
        type: u4

  named_node:
    seq:
      - id: name
        type: string
      - id: node_index
        type: node_index

  named_node_array:
    seq:
      - id: element_count
        type: u4
      - id: offset
        type: u4
      - id: array
        type: named_node_array_deref( _io.pos-4, offset, element_count )
        if: element_count != 0
    instances:
      is_empty:
        value: element_count == 0

  named_node_array_deref:
    params:
      - id: base
        type: u4
      - id: offset
        type: u4
      - id: element_count 
        type: u4
    instances:
      elements:
        pos: base+offset
        type: named_node
        repeat: expr
        repeat-expr: element_count

  file_signature_array:
    seq:
      - id: element_count
        type: u4
      - id: offset
        type: u4
      - id: array
        type: file_signature_array_deref( _io.pos-4, offset, element_count )
        if: element_count != 0
    instances:
      is_empty:
        value: element_count == 0

  file_signature_array_deref:
    params:
      - id: base
        type: u4
      - id: offset
        type: u4
      - id: element_count
        type: u4
    instances:
      elements:
        pos: base+offset
        type: file_signature
        repeat: expr
        repeat-expr: element_count

  file_signature:
    seq:
      - id: path
        type: string
      - type: u1
        repeat: expr
        repeat-expr: 8
      - id: timestamp
        type: timestamp

  glob_signature_array:
    seq:
      - id: element_count
        type: u4
      - id: offset
        type: u4
      - id: array
        type: glob_signature_array_deref( _io.pos-4, offset, element_count )
        if: element_count != 0
    instances:
      is_empty:
        value: element_count == 0

  glob_signature_array_deref:
    params:
      - id: base
        type: u4
      - id: offset
        type: u4
      - id: element_count
        type: u4
    instances:
      elements:
        pos: base+offset
        type: glob_signature
        repeat: expr
        repeat-expr: element_count 

  glob_signature:
    seq:
      - id: path
        type: string
      - id: hash
        type: fast_hash

  timestamp:
    seq:
      - id: as_uint64
        type: u8
