from InquirerPy import inquirer 
from InquirerPy.utils import get_style

def start_app():
    print("""

    ██████╗ ██╗   ██╗██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗             
    ██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝             
    ██████╔╝ ╚████╔╝ ██████╔╝███████║██║     █████╔╝ █████╗     ██║                
    ██╔═══╝   ╚██╔╝  ██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║                
    ██║        ██║   ██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║                
    ╚═╝        ╚═╝   ╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝                
                                                                                
    ██╗███╗   ██╗███████╗██████╗ ███████╗ ██████╗████████╗ ██████╗ ██████╗ 
    ██║████╗  ██║██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
    ██║██╔██╗ ██║███████╗██████╔╝█████╗  ██║        ██║   ██║   ██║██████╔╝
    ██║██║╚██╗██║╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
    ██║██║ ╚████║███████║██║     ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
    ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
                                                                            
    """)

    STYLE = get_style({
        "questionmark": "#39FF14 bold",      
        "answermark": "#00FF41 bold",        
        "question": "bold #D1D1D1",          
        "answer": "#00FF41 bold",            
        "pointer": "#39FF14 bold",          
        "highlighted": "bg:#003B00 #39FF14 bold", 
        "instruction": "#008F11 italic",     
        "validator": "bg:#FF0000 #FFFFFF", 
    })

    # choose filters
    print("Configure Filters")
    interface_filter = inquirer.select(message="Interface", choices=["All", "eth0", "wlan0"], default="All", style=STYLE).execute()
    ip_filter = inquirer.select(message="IP Version", choices=["All", "IPv4", "IPv6"], default="All", style=STYLE).execute()
    
    if ip_filter != "All":
        address_type_filter = inquirer.select(message="Address Type", choices=["None", "Single IP", "Subnet"], default="None", style=STYLE).execute()

        address_type_value = None
        if address_type_filter == "Single IP":
            address_type_value = inquirer.text(message=f"Enter {ip_filter} Address").execute()
        elif address_type_filter == "Subnet":
            address_type_value = inquirer.text(message="Enter CIDR").execute()

    


if __name__ == "__main__":
    start_app()