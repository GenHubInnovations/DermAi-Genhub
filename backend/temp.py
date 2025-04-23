
# import pyautogui
# import time

# print("Move your mouse to the desired location. The coordinates will be printed every 2 seconds.")
# try:
#     while True:
#         x, y = pyautogui.position()
#         print(f"X={x}, Y={y}")
#         time.sleep(2)
# except KeyboardInterrupt:
#     print("\nStopped!")


import pyautogui
import time
import os

def move_and_click(x, y, delay=2):
    """Move the mouse to a specific position, click, and wait."""
    pyautogui.moveTo(x, y, duration=1)
    time.sleep(1)
    pyautogui.click()
    print(f"Clicked at ({x}, {y})")
    time.sleep(delay)

def press_enter(delay=2):
    """Press Enter and wait."""
    pyautogui.press('enter')
    time.sleep(delay)

def type_value(value, delay=4):
    """Clear field, type value, and press Enter."""
    pyautogui.hotkey('ctrl', 'a')
    pyautogui.press('backspace')
    pyautogui.hotkey('ctrl', 'a')
    pyautogui.press('backspace')
    pyautogui.hotkey('ctrl', 'a')
    pyautogui.press('backspace')
    pyautogui.write(str(value))
    press_enter(delay)

# *Main Loop*
iteration = 86  # Start iteration count
max_iterations = 110  # Adjust if needed

try:
    while iteration <= max_iterations:  # Loop through defined number of iterations
        print(f"\n🔁 Iteration {iteration}: Starting Automation\n")

        # Start PCTRAN and make it full screen
        print("Starting PCTRAN...")
        os.system("start PCTRAN")  # Adjust if necessary

        time.sleep(5)  # Allow time for PCTRAN to open
        pyautogui.hotkey('alt', 'space')  # Open window menu
        pyautogui.press('x')  # Maximize window

        time.sleep(2)  # Short delay before testing movements

        # Steps to automate
        time.sleep(2)
        move_and_click(116, 57, 12)  # Run Btn
        move_and_click(1515, 1020, 1)  # Toggle Freeze Btn
        move_and_click(990, 140, 2)  # Power Demand Manual Btn
        move_and_click(1019, 508, 2)  # Demand Entry Form Input Field
        type_value(iteration, 2)  # Enter demand value
        move_and_click(1515, 1020, 2)  # Toggle Freeze Btn
        move_and_click(1542, 1020, 2)  # Change Run Time
        move_and_click(1542, 1020, 2)  # Change Run Time
        move_and_click(1542, 1020, 2)  # Change Run Time
        move_and_click(1542, 1020, 2)  # Change Run Time

        time.sleep(290 / 16)  # Simulate 290s run on 16x
        press_enter(2)  # Press Enter

        # Handle popups
        press_enter(2)  # "Do you want to create an Initial Condition record?" -> Yes
        press_enter(2)
        press_enter(2)  # "Save Transient Report?" -> Yes
        press_enter(2)

        # Create report folder
        move_and_click(289, 59, 2)
        move_and_click(147, 99, 2)
        pyautogui.write(f"{iteration}%")
        press_enter(2)
        press_enter(2)

        # Save Transient Report
        move_and_click(187, 433, 2)
        pyautogui.write(f"{iteration}_transient_report.txt")
        press_enter(2)

        # Handle plot data popup
        press_enter(2)
        pyautogui.press('right')
        press_enter(2)
        pyautogui.write(f"{iteration}_plot_data")
        press_enter(2)
        time.sleep(15)

        # Handle dose data popup
        press_enter(2)
        pyautogui.press('right')
        press_enter(2)
        pyautogui.write(f"{iteration}_dose_data")
        press_enter(2)
        time.sleep(15)

        # Final popup
        pyautogui.press('right')
        press_enter(2)  # Select No

        print(f"✅ Iteration {iteration} Completed Successfully!\n")

        iteration += 1  # Increment iteration count
        time.sleep(5)  # Short pause before restarting

except KeyboardInterrupt:
    print("\n⏹ Stopped by User! Exiting...")
