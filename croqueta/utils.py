# utils.py (Python 2 / Jython)

import re
import json
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import VariableSizeException, CodeUnit
from ghidra.app.services import DataTypeManagerService
from ghidra.app.script import GhidraScript
from config import PROMPTS, THEME, CUSTOM_THEMES

def find_data_type_by_name(name, tool):
    """Find a data type by its name from the data type manager."""
    service = tool.getService(DataTypeManagerService)
    data_type_managers = service.getDataTypeManagers()

    for manager in data_type_managers:
        data_type = manager.getDataType("/" + name)
        if data_type is None:
            data_type = manager.getDataType(name)
        if data_type is not None:
            return data_type

        all_data_types = manager.getAllDataTypes()
        for dt in all_data_types:
            if dt.getName().lower() == name.lower():
                return dt
    return None

def create_data_type_if_missing(type_name, tool):
    """Create missing data types (structs, pointers, arrays, typedefs)."""
    type_name = type_name.strip()
    if not type_name:
        return None

    existing_type = find_data_type_by_name(type_name, tool)
    if existing_type:
        return existing_type

    service = tool.getService(DataTypeManagerService)
    data_type_managers = service.getDataTypeManagers()

    try:
        # Pointer types
        if type_name.endswith('*') or ' *' in type_name:
            base_type_name = type_name.replace('*', '').replace(' ', '').strip()
            base_type = find_data_type_by_name(base_type_name, tool)
            if base_type is None and (base_type_name.startswith('I') or base_type_name.startswith('struct ')):
                struct_name = base_type_name.replace('struct ', '').strip() if base_type_name.startswith('struct ') else base_type_name
                for manager in data_type_managers:
                    try:
                        from ghidra.program.model.data import StructureDataType
                        new_struct = StructureDataType(struct_name, 0)
                        manager.addDataType(new_struct, None)
                        print "Created interface/struct '{}' for pointer type".format(struct_name)
                        base_type = new_struct
                        break
                    except Exception:
                        continue
            if base_type:
                for manager in data_type_managers:
                    try:
                        pointer_type = manager.getPointer(base_type)
                        if pointer_type:
                            print "Created pointer type '{}' based on '{}'".format(type_name, base_type_name)
                            return pointer_type
                    except:
                        continue

        # Array types
        array_match = re.match(r'(\w+)\s*\[(\d+)\]', type_name)
        if array_match:
            element_type_name = array_match.group(1)
            array_size = int(array_match.group(2))
            element_type = find_data_type_by_name(element_type_name, tool)
            if element_type is None:
                element_type = create_data_type_if_missing(element_type_name, tool)
            if element_type:
                for manager in data_type_managers:
                    try:
                        array_type = manager.getArray(element_type, array_size)
                        if array_type:
                            print "Created array type '{}' based on '{}'".format(type_name, element_type_name)
                            return array_type
                    except:
                        continue

        # Struct types
        if type_name.startswith('struct ') or type_name.startswith('STRUCT_'):
            struct_name = type_name.replace('struct ', '').strip()
            for manager in data_type_managers:
                try:
                    struct_type = manager.getDataType("/" + struct_name)
                    if struct_type:
                        return struct_type
                    from ghidra.program.model.data import StructureDataType
                    new_struct = StructureDataType(struct_name, 0)
                    manager.addDataType(new_struct, None)
                    print "Created empty struct type '{}'".format(struct_name)
                    return new_struct
                except Exception as e:
                    print "Failed to create struct '{}': {}".format(struct_name, str(e))
                    continue

        # Typedefs
        if '_' in type_name or type_name.isupper():
            for manager in data_type_managers:
                try:
                    void_type = manager.getDataType("void")
                    if void_type:
                        from ghidra.program.model.data import TypedefDataType
                        typedef = TypedefDataType(type_name, void_type)
                        manager.addDataType(typedef, None)
                        print "Created typedef '{}' as alias to void".format(type_name)
                        return typedef
                except Exception as e:
                    print "Failed to create typedef '{}': {}".format(type_name, str(e))
                    continue

    except Exception as e:
        print "Error creating data type '{}': {}".format(type_name, str(e))

    return None

def retype_variable(variable, new_type_name, tool):
    new_data_type = find_data_type_by_name(new_type_name, tool)
    if new_data_type is None:
        print "Data type '{}' not found, attempting to create it...".format(new_type_name)
        new_data_type = create_data_type_if_missing(new_type_name, tool)
        if new_data_type is None:
            print "Failed to find or create data type '{}'".format(new_type_name)
            return False
    try:
        variable.setDataType(new_data_type, SourceType.USER_DEFINED)
        print "Successfully retyped variable '{}' to '{}'".format(variable.getName(), new_type_name)
        return True
    except VariableSizeException as e:
        print "Variable size conflict when retyping '{}' to '{}'. Details: {}".format(variable.getName(), new_type_name, str(e))
        return False
    except Exception as e:
        print "Error retyping variable '{}' to '{}': {}".format(variable.getName(), new_type_name, str(e))
        return False

def retype_global_variable(listing, symbol, new_data_type):
    addr = symbol.getAddress()
    try:
        listing.clearCodeUnits(addr, addr.add(new_data_type.getLength() - 1), False)
        data = listing.createData(addr, new_data_type)
        if data:
            print "Retyped global variable '{}' to '{}'".format(symbol.getName(), new_data_type.getName())
        else:
            existing_data = listing.getDataAt(addr)
            if existing_data:
                existing_data.setDataType(new_data_type, SourceType.USER_DEFINED)
                print "Modified existing data type for global variable '{}' to '{}'".format(symbol.getName(), new_data_type.getName())
            else:
                print "Failed to create or modify data for global variable '{}' with type '{}'".format(symbol.getName(), new_data_type.getName())
    except Exception as e:
        print "Error retyping global variable '{}' to '{}': {}".format(symbol.getName(), new_data_type.getName(), str(e))

def retype_global_variable_with_creation(listing, symbol, new_type_name, tool):
    new_data_type = find_data_type_by_name(new_type_name, tool)
    if new_data_type is None:
        print "Data type '{}' not found for global variable, attempting to create it...".format(new_type_name)
        new_data_type = create_data_type_if_missing(new_type_name, tool)
        if new_data_type is None:
            print "Failed to find or create data type '{}' for global variable".format(new_type_name)
            return
    retype_global_variable(listing, symbol, new_data_type)

def rename_function(func, new_name):
    func.setName(new_name, SourceType.USER_DEFINED)
    print "Renamed function to '{}'".format(new_name)

def rename_symbol(symbol, new_name):
    old_name = symbol.getName()
    symbol.setName(new_name, SourceType.USER_DEFINED)
    print "Renamed variable '{}' to '{}'".format(old_name, new_name)

def process_global_variable(symbol_table, listing, old_name, new_name, new_type_name, tool):
    if old_name.startswith('_'):
        old_name = old_name[1:]
    symbols = symbol_table.getSymbols(old_name)
    symbol = next(symbols, None)
    if symbol:
        if new_name:
            rename_symbol(symbol, new_name)
        if new_type_name:
            retype_global_variable_with_creation(listing, symbol, new_type_name, tool)
    else:
        print "Global variable '{}' not found".format(old_name)

def process_local_variable(var_obj, new_name, new_type_name, tool):
    if new_name:
        rename_symbol(var_obj, new_name)
    if new_type_name:
        success = retype_variable(var_obj, new_type_name, tool)
        if not success:
            print "Warning: Failed to retype variable '{}' to '{}'.".format(var_obj.getName(), new_type_name)

def apply_selected_suggestions(func, suggestions, selected, tool):
    program = func.getProgram()
    listing = program.getListing()
    symbol_table = program.getSymbolTable()

    if selected['function_name']:
        rename_function(func, selected['function_name'])

    all_vars = list(func.getParameters()) + list(func.getLocalVariables())

    for i, var_suggestion in enumerate(selected['variables']):
        if var_suggestion:
            old_name = suggestions['variables'][i]['old_name']
            new_name = var_suggestion.get('new_name', None)
            new_type_name = var_suggestion.get('new_type', None)

            if "DAT" in old_name:
                process_global_variable(symbol_table, listing, old_name, new_name, new_type_name, tool)
            else:
                var_obj = next((v for v in all_vars if v.getName() == old_name), None)
                if var_obj:
                    process_local_variable(var_obj, new_name, new_type_name, tool)
                else:
                    print "Variable '{}' not found in function".format(old_name)

def apply_line_comments(func, comments):
    program = func.getProgram()
    listing = program.getListing()
    for address_str, comment in comments.items():
        address = program.getAddressFactory().getAddress(address_str)
        if address is None:
            print u"Warning: Invalid address {}".format(unicode(address_str))
            continue
        code_unit = listing.getCodeUnitAt(address)
        if code_unit:
            code_unit.setComment(CodeUnit.PRE_COMMENT, comment)
            print u"Added PRE comment at address {}: {}".format(unicode(address_str), unicode(comment))
        else:
            print u"Warning: No code unit found at address {}".format(unicode(address_str))
    print u"Line comments applied."


def apply_explanation(func, explanation):
    func.setComment(explanation)
    print "Added explanation as comment to the function."

def prepare_prompt(code, variables, action='rename_retype', callers_code=None):
    # Force all literals and inputs to Unicode
    def to_unicode(s):
        if isinstance(s, unicode):
            return s
        try:
            return unicode(s)
        except Exception:
            return unicode(str(s), 'utf-8', errors='ignore')

    prompt_template = PROMPTS.get(action)
    if not prompt_template:
        return None

    prompt = to_unicode(prompt_template)

    if callers_code:
        prompt += to_unicode("### Additional Context: Callers' Code\n")
        for caller_name, caller_code in callers_code.items():
            prompt += to_unicode("#### Caller: {}\n\n{}\n\n\n").format(
                to_unicode(caller_name), to_unicode(caller_code)
            )

    prompt += to_unicode("### Code:\n\n{}\n\n").format(to_unicode(code))

    if action != 'line_comments':
        prompt += to_unicode("### Variables:\n\n{}\n\n").format(
            to_unicode(json.dumps(variables, indent=2))
        )

    return prompt


def format_new_type(type_str):
    fixed_type = re.sub(r'(?<!\s)\*', ' *', type_str)
    fixed_type = re.sub(r'\*\*+', lambda m: ' ' + ' *' * len(m.group()), fixed_type)
    fixed_type = re.sub(r'\s+', ' ', fixed_type).strip()
    return fixed_type

def apply_theme_to_dialog(dialog):
    theme_colors = CUSTOM_THEMES.get(THEME, CUSTOM_THEMES['light'])
    from java.awt import Color
    dialog.setBackground(Color.decode(theme_colors['bg']))
    if hasattr(dialog, 'getComponents'):
        for component in dialog.getComponents():
            if hasattr(component, 'setBackground'):
                component.setBackground(Color.decode(theme_colors['bg']))
            if hasattr(component, 'setForeground'):
                component.setForeground(Color.decode(theme_colors['fg']))

def detect_vulnerabilities(code):
    vulnerabilities = []
    lines = code.split('\n')
    for i, line in enumerate(lines):
        if 'strcpy' in line or 'strcat' in line or 'sprintf' in line:
            vulnerabilities.append({
                'type': 'Buffer Overflow',
                'severity': 'High',
                'location': 'Line {}'.format(i+1),
                'description': 'Potential buffer overflow in {}'.format(line.strip())
            })
        if 'printf(' in line and '%' in line:
            vulnerabilities.append({
                'type': 'Format String',
                'severity': 'Medium',
                'location': 'Line {}'.format(i+1),
                'description': 'Potential format string vulnerability in {}'.format(line.strip())
            })
    return vulnerabilities

def detect_language(code):
    if 'fn ' in code or 'let ' in code or 'impl ' in code:
        return 'Rust'
    elif 'def ' in code or 'import ' in code or 'class ' in code:
        return 'Python'
    elif 'public class' in code or 'System.out' in code:
        return 'Java'
    elif 'int main' in code or '#include' in code:
        return 'C'
    elif 'std::' in code or 'cout' in code:
        return 'C++'
    else:
        return 'Unknown'
