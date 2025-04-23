# import pyautogui
# import time
# import os

# def move_and_click(x, y, delay=2):
#     """Move the mouse to a specific position, click, and wait."""
#     pyautogui.moveTo(x, y, duration=1)
#     time.sleep(1)
#     pyautogui.click()
#     print(f"Clicked at ({x}, {y})")
#     time.sleep(delay)

# def press_enter(delay=2):
#     """Press Enter and wait."""
#     pyautogui.press('enter')
#     time.sleep(delay)

# def type_value(value, delay=4):
#     """Clear field, type value, and press Enter."""
#     pyautogui.hotkey('ctrl', 'a')
#     pyautogui.press('backspace')
#     pyautogui.hotkey('ctrl', 'a')
#     pyautogui.press('backspace')
#     pyautogui.hotkey('ctrl', 'a')
#     pyautogui.press('backspace')
#     pyautogui.write(str(value))
#     press_enter(delay)

# # Start PCTRAN and make it full screen
# print("Starting PCTRAN...")
# os.system("start PCTRAN")  # Adjust if necessary

# time.sleep(5)  # Allow time for PCTRAN to open
# pyautogui.hotkey('alt', 'space')  # Open window menu
# pyautogui.press('x')  # Maximize window

# time.sleep(2)  # Short delay before testing movements

# # Steps to automate
# time.sleep(2)
# move_and_click(116, 57, 12)  # Run Btn
# move_and_click(1515, 1020, 10)  # Toggle Freeze Btn
# move_and_click(990, 140, 2)  # Power Demand Manual Btn
# move_and_click(1019, 508, 2)  # Demand Entry Form Input Field
# type_value(79, 2)  # Enter demand value
# move_and_click(1515, 1020, 2)  # Toggle Freeze Btn
# move_and_click(1542, 1020, 2)  # Change Run Time
# move_and_click(1542, 1020, 2)  # Change Run Time
# move_and_click(1542, 1020, 2)  # Change Run Time
# move_and_click(1542, 1020, 2)  # Change Run Time
# # for _ in range(4):
# #     pyautogui.press('enter')
# #     time.sleep(2)

# time.sleep(290 / 16)  # Simulate 290s run on 16x
# press_enter(2)  # Press Enter

# # Handle popups
# press_enter(2)  # "Do you want to create an Initial Condition record?" -> Yes
# press_enter(2)
# press_enter(2)  # "Save Transient Report?" -> Yes
# press_enter(2) 

# # Create report folder
# move_and_click(289, 59, 2)
# move_and_click(147, 99, 2)
# pyautogui.write("82%")
# press_enter(2)
# press_enter(2)

# # Save Transient Report
# move_and_click(187, 433, 2)
# pyautogui.write("82%_transient_report.txt")
# press_enter(2)

# # Handle plot data popup
# press_enter(2)
# # move_and_click(261, 134, 2)
# # write command to press side arrow button of keyboard
# pyautogui.press('right')
# press_enter(2)
# pyautogui.write("82%_plot_data")
# press_enter(2)
# time.sleep(15)

# # Handle dose data popup
# press_enter(2)
# # move_and_click(261, 134, 2)
# # write command to press side arrow button of keyboard
# pyautogui.press('right')
# press_enter(2)
# pyautogui.write("82%_dose_data")
# press_enter(2)
# time.sleep(15)

# # Final popup
# pyautogui.press('right')
# press_enter(2)  # "Save Transient Report?" -> Yes # Select No




import pyautogui
import time
import os

def move_and_click(x, y, delay=2):
    """Move the mouse to a specific position, click, and wait."""
    pyautogui.moveTo(x, y, duration=1)
    # time.sleep(1)
    pyautogui.click()
    print(f"Clicked at ({x}, {y})")
    time.sleep(delay)

def press_enter(delay=2):
    """Press Enter and wait."""
    pyautogui.press('enter')
    time.sleep(delay)

def type_value(value, delay=2):
    """Clear field, type value, and press Enter."""
    pyautogui.hotkey('ctrl', 'A')
    pyautogui.press('backspace')
    pyautogui.hotkey('ctrl', 'A')
    pyautogui.press('backspace')
    pyautogui.hotkey('ctrl', 'A')
    pyautogui.press('backspace')
    pyautogui.write(str(value))
    press_enter(delay)

for file_number in range(75, 76):
    time.sleep(3)
    # Start PCTRAN and make it full screen
    print(f"Starting PCTRAN for file {file_number}...")
    os.system("start PCTRAN")  # Adjust if necessary

    time.sleep(3)  # Allow time for PCTRAN to open
    pyautogui.hotkey('alt', 'space')  # Open window menu
    pyautogui.press('x')  # Maximize window

    # time.sleep(2)  # Short delay before testing movements

    # Steps to automate
    time.sleep(2)
    # move_and_click(116, 57, 12)  # Run Btn
    # move_and_click(1515, 1020, 10)  # Toggle Freeze Btn
    # move_and_click(990, 140, 2)  # Power Demand Manual Btn
    # move_and_click(1019, 508, 2)  # Demand Entry Form Input Field
    # type_value(79, 2)  # Enter demand value
    # move_and_click(1515, 1020, 2)  # Toggle Freeze Btn
    # move_and_click(1542, 1020, 2)  # Change Run Time
    # move_and_click(1542, 1020, 2)  # Change Run Time
    # move_and_click(1542, 1020, 2)  # Change Run Time
    # move_and_click(1542, 1020, 2)  # Change Run Time
    move_and_click(116, 57, 11)  # Run Btn
    move_and_click(1515, 1020, 1)  # Toggle Freeze Btn
    move_and_click(990, 140, 2)  # Power Demand Manual Btn
    move_and_click(1019, 508, 2)  # Demand Entry Form Input Field
    type_value(file_number, 2)  # Enter demand value
    move_and_click(1515, 1020, 2)  # Toggle Freeze Btn
    move_and_click(1542, 1020, 0.5)  # Change Run Time
    move_and_click(1542, 1020, 0.5)  # Change Run Time
    move_and_click(1542, 1020, 0.5)  # Change Run Time
    move_and_click(1542, 1020, 0.5)  # Change Run Time
    # for _ in range(4):
    #     pyautogui.click()
        # time.sleep(2)

    time.sleep(290 / 16)  # Simulate 290s run on 16x
    time.sleep(2)
    press_enter(2)  # Press Enter

    # Handle popups
    press_enter(2)  # "Do you want to create an Initial Condition record?" -> Yes
    press_enter(2)
    press_enter(2)  
    press_enter(2)  # "Save Transient Report?" -> Yes

    # Create report folder
    move_and_click(289, 59, 2)
    move_and_click(147, 99, 2)
    pyautogui.write(f"{file_number}%")
    press_enter(1)
    press_enter(1)

    # Save Transient Report
    move_and_click(187, 433, 2)
    pyautogui.write(f"{file_number}%_transient_report.txt")
    press_enter(1)

    # Handle plot data popup
    press_enter(1)
    # move_and_click(208, 81, 2)
    # press_enter(1)
    pyautogui.press('right')
    press_enter(1)
    pyautogui.write(f"{file_number}%_plot_data")
    press_enter(1)
    time.sleep(15)

    # Handle dose data popup
    press_enter(2)
    # move_and_click(261, 134, 2)
    # press_enter(2)
    pyautogui.press('right')
    press_enter(1)
    pyautogui.write(f"{file_number}%_dose_data")
    press_enter(1)
    time.sleep(15)

    # Final popup
    press_enter(1)  # "Save Transient Report?" -> Yes
    move_and_click(1115, 588, 2)  # Select No
