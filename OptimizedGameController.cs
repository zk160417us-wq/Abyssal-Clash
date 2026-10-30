using UnityEngine;

public class OptimizedGameController : MonoBehaviour
{
    [Header("Movement Settings")]
    [SerializeField] private float moveSpeed = 5.0f;

    [Header("Cached References")]
    private Transform playerTransform;
    private AudioSource audioComponent;

    private void Awake()
    {
        // 1. CACHE REFERENCES ONCE (Prevents running heavy lookups inside Update)
        GameObject playerObj = GameObject.FindWithTag("Player");
        if (playerObj != null)
        {
            playerTransform = playerObj.transform;
        }
        else
        {
            Debug.LogWarning("OptimizedGameController: No GameObject found with tag 'Player'!");
        }

        audioComponent = GetComponent<AudioSource>();
    }

    private void Start()
    {
        // 2. TIMED EXECUTION (Runs heavy AI/game logic 5 times a second instead of 60+)
        InvokeRepeating(nameof(ThrottledGameLogic), 0.0f, 0.2f);
    }

    private void Update()
    {
        // 3. SMOOTH FRAME-RATE INDEPENDENT MOVEMENT
        // Multiplying by Time.deltaTime ensures silky-smooth movement regardless of FPS drops
        if (playerTransform != null)
        {
            Vector3 movement = new Vector3(moveSpeed * Time.deltaTime, 0, 0);
            playerTransform.Translate(movement);
        }
    }

    private void ThrottledGameLogic()
    {
        // Put your heavy operations here (e.g., searching for targets, updating UI, pathfinding)
        // This keeps your frame rate stable by spreading out CPU calculations
    }

    public void PlaySoundEffect()
    {
        if (audioComponent != null && !audioComponent.isPlaying)
        {
            audioComponent.Play();
        }
    }
}
