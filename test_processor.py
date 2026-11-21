
from utils.data_processor import (
    load_all_evidence,
    validate_evidence
)

try:
    login_df, network_df, file_df = load_all_evidence()

    validate_evidence(login_df, network_df, file_df)

    print("\n========== TRACE-X DATA VALIDATION ==========")

    print("Login records:", len(login_df))
    print("Network records:", len(network_df))
    print("File activity records:", len(file_df))

    print("\nAll required columns are present.")
    print("Evidence loading: SUCCESS")
    print("Evidence validation: SUCCESS")

    print("\n=============================================")

except Exception as error:
    print("ERROR:", error)
