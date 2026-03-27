from InquirerPy import inquirer 
from InquirerPy.utils import get_style
from InquirerPy.validator import Validator
from prompt_toolkit.validation import ValidationError

from .utils.validator import validate_ipv4_address, validate_ipv6_address, validate_ipv4_cidr, validate_ipv6_cidr, validate_interfaces

def make_validator(validate_fn, error_msg):
    class _Validator(Validator):
        def validate(self, document):
            if not validate_fn(document.text.strip()):
                raise ValidationError(
                    message=error_msg,
                    cursor_position=document.cursor_position
                )
            
    return _Validator()

def input_filters(active_interfaces):
    STYLE = get_style({
        "questionmark": "#39FF14 bold",      
        "answermark": "#00FF41 bold",        
        "question": "bold #D1D1D1",          
        "answer": "#00FF41 bold",            
        "pointer": "#39FF14 bold",          
        "highlighted": "bg:#003B00 #39FF14 bold", 
        "instruction": "#008F11 italic",     
        "validator": "bg:#FF0000 #FFFFFF", 
        "input": "#39FF14 bold",
        "placeholder": "#003B00 bold",
    })

    validate_interfaces(active_interfaces)

    if len(active_interfaces) >= 2:
        active_interfaces.insert(0, " All")

    print(" 1) Configure Filters")
    
    interface_filter = inquirer.select(message="Interface", choices=active_interfaces, default=" All", style=STYLE).execute().strip()
    ip_filter = inquirer.select(message="IP Version", choices=[" All", " IPv4", " IPv6"], default=" All", style=STYLE).execute().strip()
    
    address_type_filter = None
    address_type_value = None
    if ip_filter != "All": 
        address_type_filter = inquirer.select(message="Address Type", choices=[" None", " Single IP", " Subnet"], default=" None", style=STYLE).execute().strip()

        filter_key = None
        if address_type_filter == "Single IP":
            filter_key = ip_filter
        elif address_type_filter == "Subnet":
            filter_key = ip_filter + "_Subnet"
        
        if filter_key:
            error_message = ""
            validators = {
                "IPv4": ("Enter IPv4 Address", validate_ipv4_address, "Must be a valid IPv4 Address"),
                "IPv6": ("Enter IPv6 Address", validate_ipv6_address, "Must be a valid IPv6 Address"),
                "IPv4_Subnet": ("Enter Subnet CIDR", validate_ipv4_cidr, "Must be a valid IPv4 Subnet in CIDR Notation"),
                "IPv6_Subnet": ("Enter Subnet CIDR", validate_ipv6_cidr, "Must be a valid IPv6 Subnet in CIDR Notation")
            }            
            

            prompt_msg, validate_fn, error_msg = validators[filter_key]
            address_type_value = inquirer.text(message=f"{prompt_msg}{error_message}", validate=make_validator(validate_fn, error_msg), invalid_message=error_msg, style=STYLE).execute().strip()       

    print("\n 2) Configure Display")
    show_detailed_info = inquirer.select(message="Show Detailed Information?", choices=[' Yes', ' No'], default=' No', style=STYLE).execute().strip()
    show_detailed_info = True if show_detailed_info == "Yes" else False

    return interface_filter, ip_filter, address_type_filter, address_type_value, show_detailed_info

